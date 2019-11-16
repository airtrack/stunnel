use std::thread;
// use std::cell::RefCell;
use std::collections::HashMap;
use std::str::from_utf8;
// use std::rc::Rc;
use std::vec::Vec;
use std::net::Shutdown;
use std::time::Duration;

use async_std::prelude::*;
use async_std::sync::{Sender, Receiver, channel};
use async_std::net::TcpStream;
use async_std::task;

use time::{get_time, Timespec};
// use super::ucp::{UcpServer, UcpStream};
use super::timer;
use super::cryptor::*;
use super::protocol::*;

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

struct PortMapValue {
    count: u32,
    tx: Sender<TunnelPortMsg>,
}

type PortMap = HashMap<u32, PortMapValue>;

impl TcpTunnel {
    pub fn new(key: Vec<u8>, stream: TcpStream) {
        task::spawn(async move {
            tcp_tunnel_core_task(key, stream).await;
        });
    }
}

impl UcpTunnel {
    pub fn new(_key: Vec<u8>, _listen_addr: String) {
        thread::spawn(move || {
            // ucp_tunnel_core_task(key, listen_addr);
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
            None => TunnelPortMsg::ClosePort
        }
    }

    async fn drop(&self) {
        self.tx.send(TunnelMsg::TunnelPortDrop(self.id)).await;
    }
}

async fn tunnel_port_write(stream: &mut &TcpStream, write_port: &TunnelWritePort) {
    loop {
        let mut buf = vec![0; 1024];
        match stream.read(&mut buf).await {
            Ok(0) => {
                let _ = stream.shutdown(Shutdown::Read);
                write_port.shutdown_write().await;
                break
            },

            Ok(n) => {
                buf.truncate(n);
                write_port.write(buf).await;
            },

            Err(_) => {
                let _ = stream.shutdown(Shutdown::Both);
                write_port.close().await;
                break
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
                    break
                }
            },

            TunnelPortMsg::ShutdownWrite => {
                let _ = stream.shutdown(Shutdown::Write);
                break
            },

            _ => {
                let _ = stream.shutdown(Shutdown::Both);
                break
            }
        }
    }
}

async fn tunnel_port_task(read_port: TunnelReadPort, write_port: TunnelWritePort) {
    let stream = match read_port.read().await {
        TunnelPortMsg::Data(cs::CONNECT, buf) => {
            TcpStream::connect(from_utf8(&buf).unwrap()).await.ok()
        },

        TunnelPortMsg::ConnectDN(domain_name, port) => {
            TcpStream::connect((from_utf8(&domain_name).unwrap(), port)).await.ok()
        },

        _ => None
    };

    let stream = match stream {
        Some(s) => s,
        None => return write_port.close().await
    };

    match stream.local_addr() {
        Ok(addr) => {
            let mut buf = Vec::new();
            let _ = std::io::Write::write_fmt(&mut buf, format_args!("{}", addr));
            write_port.connect_ok(buf).await;
        },

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

/*
struct UcpTask {
    key: Vec<u8>,
    buffer: Vec<u8>,
    alive_time: Timespec,
    encryptor: Option<Cryptor>,
    decryptor: Option<Cryptor>,
    port_map: PortMap,
    core_tx: Sender<TunnelMsg>,
    core_rx: Receiver<TunnelMsg>
}

impl UcpTask {
    fn new(key: Vec<u8>) -> UcpTask {
        let (core_tx, core_rx) = channel::bounded(200);

        UcpTask {
            key: key,
            buffer: Vec::new(),
            alive_time: get_time(),
            encryptor: None,
            decryptor: None,
            port_map: PortMap::new(),
            core_tx: core_tx,
            core_rx: core_rx
        }
    }

    fn update(&mut self, ucp: &mut UcpStream) -> bool {
        if !self.check_if_alive() {
            self.destroy();
            return false
        }

        match self.make_cryptor(ucp) {
            Ok(true) => {
                self.read_data_and_process(ucp);
                self.process_pending_tunnel_messages(ucp);
            },

            Ok(false) => { },

            Err(_) => return false
        }

        true
    }

    fn destroy(&self) {
        for (_, value) in self.port_map.iter() {
            value.tx.send(TunnelPortMsg::ClosePort);
        }
    }

    fn check_if_alive(&self) -> bool {
        let duration = get_time() - self.alive_time;
        duration.num_milliseconds() < ALIVE_TIMEOUT_TIME_MS
    }

    fn make_cryptor(&mut self, ucp: &mut UcpStream)
        -> Result<bool, TunnelError> {
        if self.encryptor.is_none() {
            self.encryptor = Some(Cryptor::new(&self.key[..]));
            let encryptor = self.encryptor.as_mut().unwrap();

            ucp.send(encryptor.ctr_as_slice());
        }

        if self.decryptor.is_none() {
            let size = CTR_SIZE + VERIFY_DATA.len();
            let mut buf = vec![0u8; size];
            let len = ucp.recv(&mut buf[..]);
            buf.truncate(len);
            self.buffer.append(&mut buf);

            if self.buffer.len() >= size {
                let ctr = self.buffer[0..CTR_SIZE].to_vec();
                self.decryptor = Some(Cryptor::with_ctr(&self.key[..], ctr));

                let decryptor = self.decryptor.as_mut().unwrap();
                let data = decryptor.decrypt(&self.buffer[CTR_SIZE..size]);
                if &data[..] != &VERIFY_DATA {
                    return Err(TunnelError {})
                }

                self.buffer.drain(0..size);
            }
        }

        Ok(self.encryptor.is_some() && self.decryptor.is_some())
    }

    fn read_data_and_process(&mut self, ucp: &mut UcpStream) {
        loop {
            let mut buf = vec![0u8; 1024];
            let len = ucp.recv(&mut buf[..]);
            match len {
                0 => { break },
                _ => {
                    buf.truncate(len);
                    self.buffer.append(&mut buf);
                }
            }
        }

        while let Some(msg) = self.parse_buffer_msg() {
            self.process_tunnel_msg(ucp, msg);
        }
    }

    fn parse_buffer_msg(&mut self) -> Option<TunnelMsg> {
        if self.buffer.is_empty() {
            return None
        }

        let mut msg = None;
        let mut consumed_bytes = 0;

        match read_cmd(&self.buffer[..]) {
            cs::HEARTBEAT => {
                msg = Some(TunnelMsg::CSHeartbeat);
                consumed_bytes = 1;
            },

            cs::OPEN_PORT => if self.buffer.len() >= 5 {
                let id = read_id(&self.buffer[..]);
                msg = Some(TunnelMsg::CSOpenPort(id));
                consumed_bytes = 5;
            },

            cs::CLOSE_PORT => if self.buffer.len() >= 5 {
                let id = read_id(&self.buffer[..]);
                msg = Some(TunnelMsg::CSClosePort(id));
                consumed_bytes = 5;
            },

            cs::SHUTDOWN_WRITE => if self.buffer.len() >= 5 {
                let id = read_id(&self.buffer[..]);
                msg = Some(TunnelMsg::CSShutdownWrite(id));
                consumed_bytes = 5;
            },

            cs::CONNECT_DOMAIN_NAME => if self.buffer.len() >= 9 {
                let total_len = get_total_packet_len(&self.buffer[..]);
                if self.buffer.len() >= total_len {
                    let (id, len) = read_id_len(&self.buffer[..]);
                    let domain = self.decryptor.as_mut().unwrap()
                        .decrypt(&self.buffer[9..(9 + len - 2)]);
                    let port = read_domain_port(&self.buffer[..]);

                    msg = Some(TunnelMsg::CSConnectDN(id, domain, port));
                    consumed_bytes = total_len;
                }
            },

            _ => if self.buffer.len() >= 9 {
                let total_len = get_total_packet_len(&self.buffer[..]);
                if self.buffer.len() >= total_len {
                    let cmd = read_cmd(&self.buffer[..]);
                    let (id, len) = read_id_len(&self.buffer[..]);
                    let data = self.decryptor.as_mut().unwrap()
                        .decrypt(&self.buffer[9..(9 + len)]);

                    msg = Some(TunnelMsg::CSData(cmd, id, data));
                    consumed_bytes = total_len;
                }
            }
        }

        if consumed_bytes > 0 {
            self.buffer.drain(0..consumed_bytes);
        }

        msg
    }

    fn process_pending_tunnel_messages(&mut self, ucp: &mut UcpStream) {
        while !ucp.is_send_buffer_overflow() {
            match self.core_rx.try_recv() {
                Some(msg) => self.process_tunnel_msg(ucp, msg),
                None => break
            }
        }
    }

    fn process_tunnel_msg(&mut self, ucp: &mut UcpStream, msg: TunnelMsg) {
        let _ = process_tunnel_msg(
            msg, &self.core_tx,
            &mut self.alive_time,
            &mut self.port_map,
            self.encryptor.as_mut().unwrap(),
            |buf| { ucp.send(buf); Ok(()) });
    }
}

fn ucp_tunnel_core_task(key: Vec<u8>, listen_addr: String) {
    let mut ucp_server = UcpServer::listen(&listen_addr[..]).unwrap();

    ucp_server.set_on_new_ucp_stream(move |ucp| {
        let u_ucp_task = Rc::new(RefCell::new(UcpTask::new(key.clone())));
        let b_ucp_task = u_ucp_task.clone();

        ucp.set_on_update(move |u| {
            u_ucp_task.borrow_mut().update(u)
        });
        ucp.set_on_broken(move |_| {
            b_ucp_task.borrow_mut().destroy()
        });
    });

    ucp_server.run();
}
*/

async fn tcp_tunnel_core_task(key: Vec<u8>, stream: TcpStream) {
    let (core_tx, core_rx) = channel(10000);

    let mut port_map = PortMap::new();
    let (reader, writer) = &mut (&stream, &stream);
    let r = async {
        let _ = process_tcp_tunnel_read(&key, &core_tx, reader).await;
        core_tx.send(TunnelMsg::CloseTunnel).await;
        let _ = stream.shutdown(Shutdown::Both);
    };
    let w = async {
        let _ = process_tcp_tunnel_write(&key, &core_tx, core_rx,
                                         writer, &mut port_map).await;
        let _ = stream.shutdown(Shutdown::Both);
    };
    let _ = r.join(w).await;

    for (_, value) in port_map.iter() {
        value.tx.send(TunnelPortMsg::ClosePort).await;
    }
}

async fn process_tcp_tunnel_read(key: &Vec<u8>, core_tx: &Sender<TunnelMsg>,
                                 stream: &mut &TcpStream) -> std::io::Result<()> {
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
            continue
        }

        let mut id = [0u8; 4];
        stream.read_exact(&mut id).await?;
        let id = u32::from_be(unsafe { *(id.as_ptr() as *const u32) });

        match op {
            cs::OPEN_PORT => {
                core_tx.send(TunnelMsg::CSOpenPort(id)).await;
            },

            cs::CLOSE_PORT => {
                core_tx.send(TunnelMsg::CSClosePort(id)).await;
            },

            cs::SHUTDOWN_WRITE => {
                core_tx.send(TunnelMsg::CSShutdownWrite(id)).await;
            },

            cs::CONNECT_DOMAIN_NAME => {
                let mut len = [0u8; 4];
                stream.read_exact(&mut len).await?;
                let len = u32::from_be(unsafe { *(len.as_ptr() as *const u32) });

                let mut buf = vec![0; len as usize];
                stream.read_exact(&mut buf).await?;

                let pos = (len - 2) as usize;
                let domain_name = decryptor.decrypt(&buf[0..pos]);
                let port = u16::from_be(unsafe { *(buf[pos..].as_ptr() as *const u16) });

                core_tx.send(TunnelMsg::CSConnectDN(id, domain_name, port)).await;
            },

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

async fn process_tcp_tunnel_write(key: &Vec<u8>,
                                  core_tx: &Sender<TunnelMsg>,
                                  core_rx: Receiver<TunnelMsg>,
                                  stream: &mut &TcpStream,
                                  port_map: &mut PortMap) -> std::io::Result<()> {
    let mut alive_time = get_time();
    let mut encryptor = Cryptor::new(&key);

    let duration = Duration::from_millis(HEARTBEAT_INTERVAL_MS as u64);
    let timer_stream = timer::interval(duration, TunnelMsg::Heartbeat);
    let mut msg_stream = timer_stream.merge(core_rx);

    stream.write_all(encryptor.ctr_as_slice()).await?;

    loop {
        match msg_stream.next().await {
            Some(TunnelMsg::Heartbeat) => {
                let duration = get_time() - alive_time;
                if duration.num_milliseconds() > ALIVE_TIMEOUT_TIME_MS {
                    break
                }
            },

            Some(TunnelMsg::CloseTunnel) => {
                break
            },

            Some(msg) => {
                process_tunnel_msg(
                    msg, core_tx, &mut alive_time,
                    port_map, &mut encryptor, stream).await?;
            },

            None => {
                break
            }
        }
    }

    Ok(())
}

async fn process_tunnel_msg(msg: TunnelMsg,
                            core_tx: &Sender<TunnelMsg>,
                            alive_time: &mut Timespec,
                            port_map: &mut PortMap,
                            encryptor: &mut Cryptor,
                            stream: &mut &TcpStream) -> std::io::Result<()> {
    match msg {
        TunnelMsg::CSHeartbeat => {
            *alive_time = get_time();
            stream.write_all(&pack_sc_heartbeat_rsp_msg()).await?;
        },

        TunnelMsg::CSOpenPort(id) => {
            *alive_time = get_time();
            let (tx, rx) = channel(1000);
            port_map.insert(id, PortMapValue { count: 2, tx: tx });

            let read_port = TunnelReadPort {
                id: id, tx: core_tx.clone(), rx: rx
            };

            let write_port = TunnelWritePort {
                id: id, tx: core_tx.clone()
            };

            task::spawn(async move {
                tunnel_port_task(read_port, write_port).await;
            });
        },

        TunnelMsg::CSClosePort(id) => {
            *alive_time = get_time();

            if let Some(value) = port_map.get(&id) {
                value.tx.send(TunnelPortMsg::ClosePort).await;
            };

            port_map.remove(&id);
        },

        TunnelMsg::CSShutdownWrite(id) => {
            *alive_time = get_time();

            if let Some(value) = port_map.get(&id) {
                value.tx.send(TunnelPortMsg::ShutdownWrite).await;
            };
        }

        TunnelMsg::CSConnectDN(id, domain_name, port) => {
            *alive_time = get_time();

            if let Some(value) = port_map.get(&id) {
                value.tx.send(TunnelPortMsg::ConnectDN(domain_name, port)).await;
            };
        },

        TunnelMsg::CSData(op, id, buf) => {
            *alive_time = get_time();

            if let Some(value) = port_map.get(&id) {
                value.tx.send(TunnelPortMsg::Data(op, buf)).await;
            };
        },

        TunnelMsg::SCClosePort(id) => {
            if let Some(value) = port_map.get(&id) {
                value.tx.send(TunnelPortMsg::ClosePort).await;
                stream.write_all(&pack_sc_close_port_msg(id)).await?;
            };

            port_map.remove(&id);
        },

        TunnelMsg::SCShutdownWrite(id) => {
            stream.write_all(&pack_sc_shutdown_write_msg(id)).await?;
        },

        TunnelMsg::SCConnectOk(id, buf) => {
            let data = encryptor.encrypt(&buf);
            stream.write_all(&pack_sc_connect_ok_msg(id, &data)).await?;
        },

        TunnelMsg::SCData(id, buf) => {
            let data = encryptor.encrypt(&buf);
            stream.write_all(&pack_sc_data_msg(id, &data)).await?;
        },

        TunnelMsg::TunnelPortDrop(id) => {
            if let Some(value) = port_map.get_mut(&id) {
                value.count -= 1;
                if value.count == 0 {
                    port_map.remove(&id);
                }
            };
        },

        _ => {}
    }

    Ok(())
}
