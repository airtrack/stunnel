use std::collections::HashMap;
use std::net::Shutdown;
use std::time::Duration;
use std::vec::Vec;

use async_std::prelude::*;
use async_std::io::{Read, Write};
use async_std::sync::{Sender, Receiver, channel};
use async_std::net::TcpStream;
use async_std::task;

use time::{get_time, Timespec};
use super::ucp::UcpStream;
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
    pub fn new(tid: u32, server_addr: String, key: Vec<u8>) -> Tunnel {
        let (tx, rx) = channel(10000);
        let tx2 = tx.clone();

        task::spawn(async move {
            loop {
                ucp_tunnel_core_task(tid, server_addr.clone(),
                                     key.clone(), rx.clone(), tx.clone()).await;
            }
        });

        Tunnel { id: 1, core_tx: tx2 }
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

async fn tcp_tunnel_core_task(
    tid: u32,
    server_addr: String,
    key: Vec<u8>,
    core_rx: Receiver<TunnelMsg>,
    core_tx: Sender<TunnelMsg>,
) {
    let stream = match TcpStream::connect(&server_addr).await {
        Ok(stream) => stream,

        Err(_) => {
            task::sleep(Duration::from_millis(1000)).await;
            return
        }
    };

    let mut port_map = PortMap::new();
    let (reader, writer) = &mut (&stream, &stream);
    let r = async {
        let _ = process_tunnel_read(key.clone(), core_tx.clone(), reader).await;
        let _ = stream.shutdown(Shutdown::Both);
    };
    let w = async {
        let _ = process_tunnel_write(tid, key.clone(), core_rx.clone(),
                                     &mut port_map, writer).await;
        let _ = stream.shutdown(Shutdown::Both);
    };
    let _ = r.join(w).await;

    info!("Tcp tunnel {} broken", tid);

    for (_, value) in port_map.iter() {
        value.tx.send(TunnelPortMsg::ClosePort).await;
    }
}

async fn ucp_tunnel_core_task(
    tid: u32,
    server_addr: String,
    key: Vec<u8>,
    core_rx: Receiver<TunnelMsg>,
    core_tx: Sender<TunnelMsg>,
) {
    let stream = UcpStream::connect(&server_addr).await;

    let mut port_map = PortMap::new();
    let (reader, writer) = &mut (&stream, &stream);
    let r = async {
        let _ = process_tunnel_read(key.clone(), core_tx.clone(), reader).await;
        stream.shutdown();
    };
    let w = async {
        let _ = process_tunnel_write(tid, key.clone(), core_rx.clone(),
                                     &mut port_map, writer).await;
        stream.shutdown();
    };
    let _ = r.join(w).await;

    info!("Ucp tunnel {} broken", tid);

    for (_, value) in port_map.iter() {
        value.tx.send(TunnelPortMsg::ClosePort).await;
    }
}

async fn process_tunnel_read<R: Read + Unpin>(
    key: Vec<u8>,
    core_tx: Sender<TunnelMsg>,
    stream: &mut R,
) -> std::io::Result<()> {
    let mut ctr = vec![0; CTR_SIZE];
    stream.read_exact(&mut ctr).await?;

    let mut decryptor = Cryptor::with_ctr(&key, ctr);

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

                let data = decryptor.decrypt(&buf);

                if op == sc::CONNECT_OK {
                    core_tx.send(TunnelMsg::SCConnectOk(id, data)).await;
                } else {
                    core_tx.send(TunnelMsg::SCData(id, data)).await;
                }
            },

            _ => break
        }
    }

    Ok(())
}

async fn process_tunnel_write<W: Write + Unpin>(
    tid: u32, key: Vec<u8>,
    core_rx: Receiver<TunnelMsg>,
    port_map: &mut PortMap,
    stream: &mut W,
) -> std::io::Result<()> {
    let mut encryptor = Cryptor::new(&key);
    let mut alive_time = get_time();

    let duration = Duration::from_millis(HEARTBEAT_INTERVAL_MS as u64);
    let timer_stream = timer::interval(duration, TunnelMsg::Heartbeat);
    let mut msg_stream = timer_stream.merge(core_rx);

    stream.write_all(encryptor.ctr_as_slice()).await?;
    stream.write_all(&encryptor.encrypt(&VERIFY_DATA)).await?;

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

async fn process_tunnel_msg<W: Write + Unpin>(
    tid: u32, msg: TunnelMsg,
    alive_time: &mut Timespec,
    port_map: &mut PortMap,
    encryptor: &mut Cryptor,
    stream: &mut W,
) -> std::io::Result<()> {
    match msg {
        TunnelMsg::CSOpenPort(id, tx) => {
            port_map.insert(id, PortMapValue {
                count: 2, tx: tx, host: String::new(), port: 0
            });

            stream.write_all(&pack_cs_open_port_msg(id)).await?;
        },

        TunnelMsg::CSConnect(id, buf) => {
            let data = encryptor.encrypt(&buf);
            stream.write_all(&pack_cs_connect_msg(id, &data)).await?;
        },

        TunnelMsg::CSConnectDN(id, buf, port) => {
            let host = String::from_utf8(buf.clone()).unwrap_or(String::new());
            info!("{}.{}: connecting {}:{}", tid, id, host, port);

            if let Some(value) = port_map.get_mut(&id) {
                value.host = host;
                value.port = port;
            }

            let data = encryptor.encrypt(&buf);
            let packed_buffer = pack_cs_connect_domain_msg(id, &data, port);
            stream.write_all(&packed_buffer).await?;
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
            let data = encryptor.encrypt(&buf);
            stream.write_all(&pack_cs_data_msg(id, &data)).await?;
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
