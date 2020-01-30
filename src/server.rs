use std::collections::HashMap;
use std::net::Shutdown;
use std::str::from_utf8;
use std::time::{Duration, Instant};
use std::vec::Vec;

use async_std::io::{Read, Write};
use async_std::net::TcpStream;
use async_std::prelude::*;
use async_std::sync::{channel, Receiver, Sender};
use async_std::task;

use super::cryptor::*;
use super::protocol::*;
use super::timer;
use super::ucp::UcpStream;

#[derive(Clone)]
enum TunnelMsg {
    CSHeartbeat,
    CSOpenPort(u32),
    CSClosePort(u32),
    CSShutdownWrite(u32),
    CSConnectDN(u32, Vec<u8>, u16),
    CSData(u8, u32, Vec<u8>),

    SCClosePort(u32),
    SCShutdownWrite(u32),
    SCConnectOk(u32, Vec<u8>),
    SCData(u32, Vec<u8>),

    TunnelPortDrop(u32),
    Heartbeat,
    CloseTunnel,
}

enum TunnelPortMsg {
    ConnectDN(Vec<u8>, u16),
    Data(u8, Vec<u8>),
    ShutdownWrite,
    ClosePort,
}

pub struct TcpTunnel;
pub struct UcpTunnel;

struct TunnelWritePort {
    id: u32,
    tx: Sender<TunnelMsg>,
}

struct TunnelReadPort {
    id: u32,
    tx: Sender<TunnelMsg>,
    rx: Receiver<TunnelPortMsg>,
}

struct Port {
    count: u32,
    tx: Sender<TunnelPortMsg>,
}

struct PortHub(HashMap<u32, Port>);

impl TcpTunnel {
    pub fn new(key: Vec<u8>, stream: TcpStream) {
        task::spawn(async move {
            tcp_tunnel_core_task(key, stream).await;
        });
    }
}

impl UcpTunnel {
    pub fn new(key: Vec<u8>, stream: UcpStream) {
        task::spawn(async move {
            ucp_tunnel_core_task(key, stream).await;
        });
    }
}

impl TunnelWritePort {
    async fn connect_ok(&self, buf: Vec<u8>) {
        self.tx.send(TunnelMsg::SCConnectOk(self.id, buf)).await;
    }

    async fn write(&self, buf: Vec<u8>) {
        self.tx.send(TunnelMsg::SCData(self.id, buf)).await;
    }

    async fn shutdown_write(&self) {
        self.tx.send(TunnelMsg::SCShutdownWrite(self.id)).await;
    }

    async fn close(&self) {
        self.tx.send(TunnelMsg::SCClosePort(self.id)).await;
    }

    async fn drop(&self) {
        self.tx.send(TunnelMsg::TunnelPortDrop(self.id)).await;
    }
}

impl TunnelReadPort {
    async fn read(&self) -> TunnelPortMsg {
        match self.rx.recv().await {
            Some(msg) => msg,
            None => TunnelPortMsg::ClosePort,
        }
    }

    async fn drop(&self) {
        self.tx.send(TunnelMsg::TunnelPortDrop(self.id)).await;
    }
}

impl PortHub {
    fn new() -> Self {
        PortHub(HashMap::new())
    }

    fn add_port(&mut self, id: u32, tx: Sender<TunnelPortMsg>) {
        self.0.insert(id, Port { count: 2, tx: tx });
    }

    fn drop_port(&mut self, id: u32) {
        if let Some(value) = self.0.get_mut(&id) {
            value.count -= 1;
            if value.count == 0 {
                self.0.remove(&id);
            }
        };
    }

    fn clear_ports(&mut self) {
        self.0.clear();
    }

    fn client_close_port(&mut self, id: u32) {
        self.0.remove(&id);
    }

    fn server_close_port(&mut self, id: u32) {
        self.0.remove(&id);
    }

    async fn connect(&mut self, id: u32, domain: Vec<u8>, port: u16) {
        self.try_send_msg(id, TunnelPortMsg::ConnectDN(domain, port))
            .await;
    }

    async fn client_send_data(&mut self, id: u32, op: u8, buf: Vec<u8>) {
        self.try_send_msg(id, TunnelPortMsg::Data(op, buf)).await;
    }

    async fn client_shutdown(&mut self, id: u32) {
        self.try_send_msg(id, TunnelPortMsg::ShutdownWrite).await;
    }

    async fn try_send_msg(&mut self, id: u32, msg: TunnelPortMsg) {
        if let Some(value) = self.0.get(&id) {
            if value.tx.is_full() {
                self.0.remove(&id);
            } else {
                value.tx.send(msg).await;
            }
        }
    }
}

async fn tunnel_port_write(stream: &mut &TcpStream, write_port: &TunnelWritePort) {
    loop {
        let mut buf = vec![0; 1024];
        match stream.read(&mut buf).await {
            Ok(0) => {
                let _ = stream.shutdown(Shutdown::Read);
                write_port.shutdown_write().await;
                break;
            }

            Ok(n) => {
                buf.truncate(n);
                write_port.write(buf).await;
            }

            Err(_) => {
                let _ = stream.shutdown(Shutdown::Both);
                write_port.close().await;
                break;
            }
        }
    }
}

async fn tunnel_port_read(stream: &mut &TcpStream, read_port: &TunnelReadPort) {
    loop {
        match read_port.read().await {
            TunnelPortMsg::Data(cs::DATA, buf) => {
                if stream.write_all(&buf).await.is_err() {
                    let _ = stream.shutdown(Shutdown::Both);
                    break;
                }
            }

            TunnelPortMsg::ShutdownWrite => {
                let _ = stream.shutdown(Shutdown::Write);
                break;
            }

            _ => {
                let _ = stream.shutdown(Shutdown::Both);
                break;
            }
        }
    }
}

async fn tunnel_port_task(read_port: TunnelReadPort, write_port: TunnelWritePort) {
    let stream = match read_port.read().await {
        TunnelPortMsg::Data(cs::CONNECT, buf) => {
            TcpStream::connect(from_utf8(&buf).unwrap()).await.ok()
        }

        TunnelPortMsg::ConnectDN(domain_name, port) => {
            TcpStream::connect((from_utf8(&domain_name).unwrap(), port))
                .await
                .ok()
        }

        _ => None,
    };

    let stream = match stream {
        Some(s) => s,
        None => return write_port.close().await,
    };

    match stream.local_addr() {
        Ok(addr) => {
            let mut buf = Vec::new();
            let _ = std::io::Write::write_fmt(&mut buf, format_args!("{}", addr));
            write_port.connect_ok(buf).await;
        }

        Err(_) => {
            return write_port.close().await;
        }
    }

    let (reader, writer) = &mut (&stream, &stream);
    let w = tunnel_port_write(reader, &write_port);
    let r = tunnel_port_read(writer, &read_port);
    let _ = r.join(w).await;

    read_port.drop().await;
    write_port.drop().await;
}

async fn tcp_tunnel_core_task(key: Vec<u8>, stream: TcpStream) {
    let (core_tx, core_rx) = channel(10000);

    let mut port_hub = PortHub::new();
    let (reader, writer) = &mut (&stream, &stream);
    let r = async {
        let _ = process_tunnel_read(key.clone(), core_tx.clone(), reader).await;
        core_tx.send(TunnelMsg::CloseTunnel).await;
        let _ = stream.shutdown(Shutdown::Both);
    };
    let w = async {
        let _ = process_tunnel_write(key.clone(), core_tx.clone(), core_rx, &mut port_hub, writer)
            .await;
        let _ = stream.shutdown(Shutdown::Both);
    };
    let _ = r.join(w).await;

    port_hub.clear_ports();
}

async fn ucp_tunnel_core_task(key: Vec<u8>, stream: UcpStream) {
    let (core_tx, core_rx) = channel(10000);

    let mut port_hub = PortHub::new();
    let (reader, writer) = &mut (&stream, &stream);
    let r = async {
        let _ = process_tunnel_read(key.clone(), core_tx.clone(), reader).await;
        core_tx.send(TunnelMsg::CloseTunnel).await;
        stream.shutdown();
    };
    let w = async {
        let _ = process_tunnel_write(key.clone(), core_tx.clone(), core_rx, &mut port_hub, writer)
            .await;
        stream.shutdown();
    };
    let _ = r.join(w).await;

    port_hub.clear_ports();
}

async fn process_tunnel_read<R: Read + Unpin>(
    key: Vec<u8>,
    core_tx: Sender<TunnelMsg>,
    stream: &mut R,
) -> std::io::Result<()> {
    let mut ctr = vec![0; Cryptor::ctr_size()];
    stream.read_exact(&mut ctr).await?;

    let mut decryptor = Cryptor::with_ctr(&key, ctr);

    let mut buf = vec![0; VERIFY_DATA.len()];
    stream.read_exact(&mut buf).await?;

    let data = decryptor.decrypt(&buf);
    if &data != &VERIFY_DATA {
        return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
    }

    loop {
        let mut op = [0u8; 1];
        stream.read_exact(&mut op).await?;
        let op = op[0];

        if op == cs::HEARTBEAT {
            core_tx.send(TunnelMsg::CSHeartbeat).await;
            continue;
        }

        let mut id = [0u8; 4];
        stream.read_exact(&mut id).await?;
        let id = u32::from_be(unsafe { *(id.as_ptr() as *const u32) });

        match op {
            cs::OPEN_PORT => {
                core_tx.send(TunnelMsg::CSOpenPort(id)).await;
            }

            cs::CLOSE_PORT => {
                core_tx.send(TunnelMsg::CSClosePort(id)).await;
            }

            cs::SHUTDOWN_WRITE => {
                core_tx.send(TunnelMsg::CSShutdownWrite(id)).await;
            }

            cs::CONNECT_DOMAIN_NAME => {
                let mut len = [0u8; 4];
                stream.read_exact(&mut len).await?;
                let len = u32::from_be(unsafe { *(len.as_ptr() as *const u32) });

                let mut buf = vec![0; len as usize];
                stream.read_exact(&mut buf).await?;

                let pos = (len - 2) as usize;
                let domain_name = decryptor.decrypt(&buf[0..pos]);
                let port = u16::from_be(unsafe { *(buf[pos..].as_ptr() as *const u16) });

                core_tx
                    .send(TunnelMsg::CSConnectDN(id, domain_name, port))
                    .await;
            }

            _ => {
                let mut len = [0u8; 4];
                stream.read_exact(&mut len).await?;
                let len = u32::from_be(unsafe { *(len.as_ptr() as *const u32) });

                let mut buf = vec![0; len as usize];
                stream.read_exact(&mut buf).await?;

                let data = decryptor.decrypt(&buf);
                core_tx.send(TunnelMsg::CSData(op, id, data)).await;
            }
        }
    }
}

async fn process_tunnel_write<W: Write + Unpin>(
    key: Vec<u8>,
    core_tx: Sender<TunnelMsg>,
    core_rx: Receiver<TunnelMsg>,
    port_hub: &mut PortHub,
    stream: &mut W,
) -> std::io::Result<()> {
    let mut alive_time = Instant::now();
    let mut encryptor = Cryptor::new(&key);

    let duration = Duration::from_millis(HEARTBEAT_INTERVAL_MS as u64);
    let timer_stream = timer::interval(duration, TunnelMsg::Heartbeat);
    let mut msg_stream = timer_stream.merge(core_rx);

    stream.write_all(encryptor.ctr_as_slice()).await?;

    loop {
        match msg_stream.next().await {
            Some(TunnelMsg::Heartbeat) => {
                let duration = Instant::now() - alive_time;
                if duration.as_millis() > ALIVE_TIMEOUT_TIME_MS {
                    break;
                }
            }

            Some(TunnelMsg::CloseTunnel) => break,

            Some(msg) => {
                process_tunnel_msg(
                    msg,
                    &core_tx,
                    &mut alive_time,
                    port_hub,
                    &mut encryptor,
                    stream,
                )
                .await?;
            }

            None => break,
        }
    }

    Ok(())
}

async fn process_tunnel_msg<W: Write + Unpin>(
    msg: TunnelMsg,
    core_tx: &Sender<TunnelMsg>,
    alive_time: &mut Instant,
    port_hub: &mut PortHub,
    encryptor: &mut Cryptor,
    stream: &mut W,
) -> std::io::Result<()> {
    match msg {
        TunnelMsg::CSHeartbeat => {
            *alive_time = Instant::now();
            stream.write_all(&pack_sc_heartbeat_rsp_msg()).await?;
        }

        TunnelMsg::CSOpenPort(id) => {
            *alive_time = Instant::now();
            let (tx, rx) = channel(1000);
            port_hub.add_port(id, tx);

            let read_port = TunnelReadPort {
                id: id,
                tx: core_tx.clone(),
                rx: rx,
            };

            let write_port = TunnelWritePort {
                id: id,
                tx: core_tx.clone(),
            };

            task::spawn(async move {
                tunnel_port_task(read_port, write_port).await;
            });
        }

        TunnelMsg::CSClosePort(id) => {
            *alive_time = Instant::now();
            port_hub.client_close_port(id);
        }

        TunnelMsg::CSShutdownWrite(id) => {
            *alive_time = Instant::now();
            port_hub.client_shutdown(id).await;
        }

        TunnelMsg::CSConnectDN(id, domain, port) => {
            *alive_time = Instant::now();
            port_hub.connect(id, domain, port).await;
        }

        TunnelMsg::CSData(op, id, buf) => {
            *alive_time = Instant::now();
            port_hub.client_send_data(id, op, buf).await;
        }

        TunnelMsg::SCClosePort(id) => {
            port_hub.server_close_port(id);
            stream.write_all(&pack_sc_close_port_msg(id)).await?;
        }

        TunnelMsg::SCShutdownWrite(id) => {
            stream.write_all(&pack_sc_shutdown_write_msg(id)).await?;
        }

        TunnelMsg::SCConnectOk(id, buf) => {
            let data = encryptor.encrypt(&buf);
            stream.write_all(&pack_sc_connect_ok_msg(id, &data)).await?;
        }

        TunnelMsg::SCData(id, buf) => {
            let data = encryptor.encrypt(&buf);
            stream.write_all(&pack_sc_data_msg(id, &data)).await?;
        }

        TunnelMsg::TunnelPortDrop(id) => {
            port_hub.drop_port(id);
        }

        _ => {}
    }

    Ok(())
}
