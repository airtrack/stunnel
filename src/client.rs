// use std::thread;
// use std::cell::RefCell;
use std::collections::HashMap;
use std::net::Shutdown;
use std::time::Duration;
// use std::rc::Rc;
use std::vec::Vec;

use async_std::prelude::*;
use async_std::sync::{Sender, Receiver, channel};
use async_std::net::TcpStream;
use async_std::future::join;
use async_std::task;

use time::{get_time, Timespec};
// use super::ucp::{UcpClient, UcpStream};
use super::timer;
use super::cryptor::*;
use super::protocol::*;

#[derive(Clone)]
enum TunnelMsg {
    CSOpenPort(u32, Sender<TunnelPortMsg>),
    CSConnect(u32, Vec<u8>),
    CSConnectDN(u32, Vec<u8>, u16),
    CSShutdownWrite(u32),
    CSClosePort(u32),
    CSData(u32, Vec<u8>),

    SCHeartbeat,
    SCClosePort(u32),
    SCShutdownWrite(u32),
    SCConnectOk(u32, Vec<u8>),
    SCData(u32, Vec<u8>),

    Heartbeat,
    TunnelPortDrop(u32)
}

pub enum TunnelPortMsg {
    ConnectOk(Vec<u8>),
    Data(Vec<u8>),
    ShutdownWrite,
    ClosePort,
}

pub struct Tunnel {
    id: u32,
    core_tx: Sender<TunnelMsg>,
}

pub struct TcpTunnel;
pub struct UcpTunnel;

pub struct TunnelWritePort {
    id: u32,
    tx: Sender<TunnelMsg>,
}

pub struct TunnelReadPort {
    id: u32,
    tx: Sender<TunnelMsg>,
    rx: Receiver<TunnelPortMsg>,
}

impl Tunnel {
    pub async fn open_port(&mut self) -> (TunnelWritePort, TunnelReadPort) {
        let core_tx1 = self.core_tx.clone();
        let core_tx2 = self.core_tx.clone();
        let id = self.id;
        self.id += 1;

        let (tx, rx) = channel(500);
        self.core_tx.send(TunnelMsg::CSOpenPort(id, tx)).await;

        (TunnelWritePort { id: id, tx: core_tx1 },
         TunnelReadPort { id: id, tx: core_tx2, rx: rx })
    }
}

impl TcpTunnel {
    pub fn new(tid: u32, server_addr: String, key: Vec<u8>) -> Tunnel {
        let (tx, rx) = channel(10000);
        let tx2 = tx.clone();

        task::spawn(async move {
            loop {
                tcp_tunnel_core_task(tid, server_addr.clone(),
                                     key.clone(), rx.clone(), tx.clone()).await;
            }
        });

        Tunnel { id: 1, core_tx: tx2 }
    }
}

impl UcpTunnel {
    pub fn new(_tid: u32, _server_addr: String, _key: Vec<u8>) -> Tunnel {
        let (tx, _rx) = channel(10000);

/*
        thread::spawn(move || {
            ucp_tunnel_core_task(tid, server_addr, key, Rc::new(rx));
        });
*/
        Tunnel { id: 1, core_tx: tx }
    }
}

impl TunnelWritePort {
    pub async fn write(&self, buf: Vec<u8>) {
        self.tx.send(TunnelMsg::CSData(self.id, buf)).await;
    }

    pub async fn connect(&self, buf: Vec<u8>) {
        self.tx.send(TunnelMsg::CSConnect(self.id, buf)).await;
    }

    pub async fn connect_domain_name(&self, buf: Vec<u8>, port: u16) {
        self.tx.send(TunnelMsg::CSConnectDN(self.id, buf, port)).await;
    }

    pub async fn shutdown_write(&self) {
        self.tx.send(TunnelMsg::CSShutdownWrite(self.id)).await;
    }

    pub async fn close(&self) {
        self.tx.send(TunnelMsg::CSClosePort(self.id)).await;
    }

    pub async fn drop(&self) {
        self.tx.send(TunnelMsg::TunnelPortDrop(self.id)).await;
    }
}

impl TunnelReadPort {
    pub async fn read(&self) -> TunnelPortMsg {
        match self.rx.recv().await {
            Some(msg) => msg,
            None => TunnelPortMsg::ClosePort
        }
    }

    pub async fn drop(&self) {
        self.tx.send(TunnelMsg::TunnelPortDrop(self.id)).await;
    }
}

struct PortMapValue {
    host: String,
    port: u16,
    count: u32,
    tx: Sender<TunnelPortMsg>,
}

type PortMap = HashMap<u32, PortMapValue>;

/*
struct UcpTask {
    tid: u32,
    key: Vec<u8>,
    buffer: Vec<u8>,
    alive_time: Timespec,
    heartbeat_time: Timespec,
    encryptor: Option<Cryptor>,
    decryptor: Option<Cryptor>,
    port_map: Rc<RefCell<PortMap>>,
    core_rx: Rc<Receiver<TunnelMsg>>
}

impl UcpTask {
    fn new(tid: u32, key: Vec<u8>, port_map: Rc<RefCell<PortMap>>,
           core_rx: Rc<Receiver<TunnelMsg>>) -> UcpTask {
        UcpTask {
            tid: tid, key: key,
            buffer: Vec::new(),
            alive_time: get_time(),
            heartbeat_time: get_time(),
            encryptor: None, decryptor: None,
            port_map: port_map, core_rx: core_rx
        }
    }

    fn update(&mut self, ucp: &mut UcpStream) -> bool {
        if !self.heartbeat(ucp) {
            return false
        }

        if self.make_cryptor(ucp) {
            self.read_data_and_process(ucp);
            self.process_pending_tunnel_messages(ucp);
        }

        true
    }

    fn heartbeat(&mut self, ucp: &mut UcpStream) -> bool {
        let cur_time = get_time();
        let duration = cur_time - self.alive_time;
        if duration.num_milliseconds() > ALIVE_TIMEOUT_TIME_MS {
            return false
        }

        let interval = cur_time - self.heartbeat_time;
        if interval.num_milliseconds() > HEARTBEAT_INTERVAL_MS {
            ucp.send(&pack_cs_heartbeat_msg());
            self.heartbeat_time = cur_time;
        }
        true
    }

    fn make_cryptor(&mut self, ucp: &mut UcpStream) -> bool {
        if self.encryptor.is_none() {
            self.encryptor = Some(Cryptor::new(&self.key[..]));
            let encryptor = self.encryptor.as_mut().unwrap();

            ucp.send(encryptor.ctr_as_slice());
            ucp.send(&encryptor.encrypt(&VERIFY_DATA)[..]);
        }

        if self.decryptor.is_none() {
            let mut buf = vec![0u8; CTR_SIZE];
            let len = ucp.recv(&mut buf[..]);
            buf.truncate(len);
            self.buffer.append(&mut buf);

            if self.buffer.len() >= CTR_SIZE {
                let ctr = self.buffer[0..CTR_SIZE].to_vec();
                self.buffer.drain(0..CTR_SIZE);
                self.decryptor = Some(Cryptor::with_ctr(&self.key[..], ctr));
            }
        }

        self.encryptor.is_some() && self.decryptor.is_some()
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
            sc::HEARTBEAT_RSP => {
                msg = Some(TunnelMsg::SCHeartbeat);
                consumed_bytes = 1;
            },

            sc::CLOSE_PORT => if self.buffer.len() >= 5 {
                let id = read_id(&self.buffer[..]);
                msg = Some(TunnelMsg::SCClosePort(id));
                consumed_bytes = 5;
            },

            sc::SHUTDOWN_WRITE => if self.buffer.len() >= 5 {
                let id = read_id(&self.buffer[..]);
                msg = Some(TunnelMsg::SCShutdownWrite(id));
                consumed_bytes = 5;
            },

            sc::CONNECT_OK => if self.buffer.len() >= 9 {
                let total_len = get_total_packet_len(&self.buffer[..]);
                if self.buffer.len() >= total_len {
                    let (id, len) = read_id_len(&self.buffer[..]);
                    let data = self.decryptor.as_mut().unwrap()
                        .decrypt(&self.buffer[9..(9 + len)]);

                    msg = Some(TunnelMsg::SCConnectOk(id, data));
                    consumed_bytes = total_len;
                }
            },

            sc::DATA => if self.buffer.len() >= 9 {
                let total_len = get_total_packet_len(&self.buffer[..]);
                if self.buffer.len() >= total_len {
                    let (id, len) = read_id_len(&self.buffer[..]);
                    let data = self.decryptor.as_mut().unwrap()
                        .decrypt(&self.buffer[9..(9 + len)]);

                    msg = Some(TunnelMsg::SCData(id, data));
                    consumed_bytes = total_len;
                }
            },

            _ => {}
        }

        if consumed_bytes > 0 {
            self.buffer.drain(0..consumed_bytes);
        }

        msg
    }

    fn process_pending_tunnel_messages(&mut self, ucp: &mut UcpStream) {
        while let Some(msg) = self.core_rx.try_recv() {
            self.process_tunnel_msg(ucp, msg);
        }
    }

    fn process_tunnel_msg(&mut self, ucp: &mut UcpStream, msg: TunnelMsg) {
        let _ = process_tunnel_msg(
            self.tid, msg, &mut self.alive_time,
            &mut *self.port_map.borrow_mut(),
            self.encryptor.as_mut().unwrap(),
            |buf| { ucp.send(buf); Ok(()) });
    }
}

fn ucp_tunnel_core_task(tid: u32, server_addr: String, key: Vec<u8>,
                        core_rx: Rc<Receiver<TunnelMsg>>) {
    loop {
        let port_map = Rc::new(RefCell::new(PortMap::new()));
        let mut ucp_client = UcpClient::connect(&server_addr[..]);
        let mut ucp_task = UcpTask::new(
            tid, key.clone(), port_map.clone(), core_rx.clone());

        ucp_client.set_on_update(move |ucp| { ucp_task.update(ucp) });
        ucp_client.set_on_broken(|_| {});
        ucp_client.run();

        info!("tunnel {} broken", tid);
        for (_, value) in port_map.borrow().iter() {
            value.tx.send(TunnelPortMsg::ClosePort);
        }
    }
}
*/

async fn tcp_tunnel_core_task(tid: u32, server_addr: String, key: Vec<u8>,
                              core_rx: Receiver<TunnelMsg>,
                              core_tx: Sender<TunnelMsg>) {
    let stream = match TcpStream::connect(&server_addr[..]).await {
        Ok(stream) => stream,

        Err(_) => {
            task::sleep(Duration::from_millis(1000)).await;
            /*task::spawn(async move {
                tcp_tunnel_core_task(tid, server_addr, key, core_rx, core_tx).await;
            });*/
            return
        }
    };

    let mut port_map = PortMap::new();
    let (reader, writer) = &mut (&stream, &stream);
    let r = process_tcp_tunnel_read(key.clone(), reader, core_tx.clone());
    let w = process_tcp_tunnel_write(tid, key.clone(), core_rx.clone(),
                                     writer, &mut port_map);
    let _ = join!(r, w).await;

    info!("Tcp tunnel {} broken", tid);
    let _ = stream.shutdown(Shutdown::Both);

    for (_, value) in port_map.iter() {
        value.tx.send(TunnelPortMsg::ClosePort).await;
    }

    /*task::spawn(async move {
        tcp_tunnel_core_task(tid, server_addr, key, core_rx, core_tx).await;
    });*/
}

async fn process_tcp_tunnel_read(key: Vec<u8>, stream: &mut &TcpStream,
                                 core_tx: Sender<TunnelMsg>) -> std::io::Result<()> {
    let mut ctr = vec![0; CTR_SIZE];
    stream.read_exact(&mut ctr).await?;

    let mut decryptor = Cryptor::with_ctr(&key[..], ctr);

    loop {
        let mut op = [0u8; 1];
        stream.read_exact(&mut op).await?;
        let op = op[0];

        if op == sc::HEARTBEAT_RSP {
            core_tx.send(TunnelMsg::SCHeartbeat).await;
            continue
        }

        let mut id = [0u8; 4];
        stream.read_exact(&mut id).await?;
        let id = u32::from_be(unsafe { *(id.as_ptr() as *const u32) });

        match op {
            sc::CLOSE_PORT => {
                core_tx.send(TunnelMsg::SCClosePort(id)).await;
            },

            sc::SHUTDOWN_WRITE => {
                core_tx.send(TunnelMsg::SCShutdownWrite(id)).await;
            },

            sc::CONNECT_OK | sc::DATA => {
                let mut len = [0u8; 4];
                stream.read_exact(&mut len).await?;
                let len = u32::from_be(unsafe { *(len.as_ptr() as *const u32) });

                let mut buf = vec![0; len as usize];
                stream.read_exact(&mut buf).await?;

                let data = decryptor.decrypt(&buf[..]);

                if op == sc::CONNECT_OK {
                    core_tx.send(TunnelMsg::SCConnectOk(id, data)).await;
                } else {
                    core_tx.send(TunnelMsg::SCData(id, data)).await;
                }
            },

            _ => break
        }
    }

    let _ = stream.shutdown(Shutdown::Both);
    Ok(())
}

async fn process_tcp_tunnel_write(tid: u32, key: Vec<u8>,
                                  core_rx: Receiver<TunnelMsg>,
                                  stream: &mut &TcpStream,
                                  port_map: &mut PortMap) -> std::io::Result<()> {
    let mut encryptor = Cryptor::new(&key[..]);
    let mut alive_time = get_time();

    let duration = Duration::from_millis(HEARTBEAT_INTERVAL_MS as u64);
    let timer_stream = timer::interval(duration, TunnelMsg::Heartbeat);
    let mut msg_stream = timer_stream.merge(core_rx);

    stream.write_all(encryptor.ctr_as_slice()).await?;
    stream.write_all(&encryptor.encrypt(&VERIFY_DATA)[..]).await?;

    loop {
        match msg_stream.next().await {
            Some(TunnelMsg::Heartbeat) => {
                let duration = get_time() - alive_time;
                if duration.num_milliseconds() > ALIVE_TIMEOUT_TIME_MS {
                    break
                }
                stream.write_all(&pack_cs_heartbeat_msg()).await?;
            },

            Some(msg) => {
                process_tunnel_msg(
                    tid, msg, &mut alive_time,
                    port_map, &mut encryptor, stream).await?;
            },

            None => {
                break
            }
        }
    }

    Ok(())
}

async fn process_tunnel_msg(tid: u32, msg: TunnelMsg,
                            alive_time: &mut Timespec,
                            port_map: &mut PortMap,
                            encryptor: &mut Cryptor,
                            stream: &mut &TcpStream) -> std::io::Result<()> {
    match msg {
        TunnelMsg::CSOpenPort(id, tx) => {
            port_map.insert(id, PortMapValue {
                count: 2, tx: tx, host: String::new(), port: 0
            });

            stream.write_all(&pack_cs_open_port_msg(id)).await?;
        },

        TunnelMsg::CSConnect(id, buf) => {
            let data = encryptor.encrypt(&buf[..]);
            stream.write_all(&pack_cs_connect_msg(id, &data[..])[..]).await?;
        },

        TunnelMsg::CSConnectDN(id, buf, port) => {
            let host = String::from_utf8(buf.clone()).unwrap_or(String::new());
            info!("{}.{}: connecting {}:{}", tid, id, host, port);

            if let Some(value) = port_map.get_mut(&id) {
                value.host = host;
                value.port = port;
            }

            let data = encryptor.encrypt(&buf[..]);
            let packed_buffer =
                pack_cs_connect_domain_msg(id, &data[..], port);
            stream.write_all(&packed_buffer[..]).await?;
        },

        TunnelMsg::CSShutdownWrite(id) => {
            match port_map.get(&id) {
                Some(value) => {
                    info!("{}.{}: client shutdown write {}:{}",
                          tid, id, value.host, value.port);
                },

                None => {
                    info!("{}.{}: client shutdown write unknown server", tid, id);
                }
            }

            stream.write_all(&pack_cs_shutdown_write_msg(id)).await?;
        },

        TunnelMsg::CSData(id, buf) => {
            let data = encryptor.encrypt(&buf[..]);
            stream.write_all(&pack_cs_data_msg(id, &data[..])[..]).await?;
        },

        TunnelMsg::CSClosePort(id) => {
            match port_map.get(&id) {
                Some(value) => {
                    info!("{}.{}: client close {}:{}",
                          tid, id, value.host, value.port);
                    value.tx.send(TunnelPortMsg::ClosePort).await;
                    stream.write_all(&pack_cs_close_port_msg(id)).await?;
                },

                None => {
                    info!("{}.{}: client close unknown server", tid, id);
                }
            }

            port_map.remove(&id);
        },

        TunnelMsg::SCHeartbeat => {
            *alive_time = get_time();
        },

        TunnelMsg::SCClosePort(id) => {
            *alive_time = get_time();

            match port_map.get(&id) {
                Some(value) => {
                    info!("{}.{}: server close {}:{}",
                          tid, id, value.host, value.port);

                    value.tx.send(TunnelPortMsg::ClosePort).await;
                },

                None => {
                    info!("{}.{}: server close unknown client", tid, id);
                }
            }

            port_map.remove(&id);
        },

        TunnelMsg::SCShutdownWrite(id) => {
            *alive_time = get_time();

            match port_map.get(&id) {
                Some(value) => {
                    info!("{}.{}: server shutdown write {}:{}",
                          tid, id, value.host, value.port);

                    value.tx.send(TunnelPortMsg::ShutdownWrite).await;
                },

                None => {
                    info!("{}.{}: server shutdown write unknown client", tid, id);
                }
            }
        },

        TunnelMsg::SCConnectOk(id, buf) => {
            *alive_time = get_time();

            match port_map.get(&id) {
                Some(value) => {
                    info!("{}.{}: connect {}:{} ok",
                          tid, id, value.host, value.port);

                    value.tx.send(TunnelPortMsg::ConnectOk(buf)).await;
                },

                None => {
                    info!("{}.{}: connect unknown server ok", tid, id);
                }
            }
        },

        TunnelMsg::SCData(id, buf) => {
            *alive_time = get_time();
            if let Some(value) = port_map.get(&id) {
                value.tx.send(TunnelPortMsg::Data(buf)).await;
            };
        },

        TunnelMsg::TunnelPortDrop(id) => {
            if let Some(value) = port_map.get_mut(&id) {
                value.count = value.count - 1;
                if value.count == 0 {
                    info!("{}.{}: drop tunnel port {}:{}",
                          tid, id, value.host, value.port);
                    port_map.remove(&id);
                }
            } else {
                info!("{}.{}: drop unknown tunnel port", tid, id);
            }
        },

        _ => {}
    }

    Ok(())
}
