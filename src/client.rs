use std::collections::HashMap;
use std::net::Shutdown;
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::vec::Vec;

use async_std::io::{Read, Write};
use async_std::net::TcpStream;
use async_std::prelude::*;
use async_std::task;

use futures::channel::mpsc::{channel, Receiver, Sender};
use futures::sink::SinkExt;

use super::cryptor::*;
use super::protocol::*;
use super::timer;
use super::ucp::{UcpStream, UcpStreamMetrics};
use super::util::*;

#[derive(Clone)]
enum TunnelMsg {
    CSOpenPort(u32, Sender<TunnelPortMsg>),
    CSConnect(u32, Vec<u8>),
    CSConnectDN(u32, Vec<u8>, u16),
    CSUdpAssociate(u32, Vec<u8>),
    CSShutdownWrite(u32),
    CSClosePort(u32),
    CSData(u32, Vec<u8>),

    SCHeartbeat,
    SCClosePort(u32),
    SCShutdownWrite(u32),
    SCConnectOk(u32, Vec<u8>),
    SCData(u32, Vec<u8>),

    Heartbeat,
    TunnelPortHalfDrop(u32),
}

pub enum TunnelPortMsg {
    ConnectOk(Vec<u8>),
    Data(Vec<u8>),
    ShutdownWrite,
    ClosePort,
}

pub struct Tunnel {
    id: u32,
    senders: SubSenders<TunnelMsg>,
    main_sender: MainSender<TunnelMsg>,
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
    rx: Option<Receiver<TunnelPortMsg>>,
}

impl Tunnel {
    pub async fn open_port(&mut self) -> (TunnelWritePort, TunnelReadPort) {
        let id = self.id;
        self.id += 1;

        let (tx, rx) = channel(1000);
        let _ = self.main_sender.send(TunnelMsg::CSOpenPort(id, tx)).await;

        let sender = self.senders.get_one_sender();

        (
            TunnelWritePort {
                id: id,
                tx: sender.clone(),
            },
            TunnelReadPort {
                id: id,
                tx: sender.clone(),
                rx: Some(rx),
            },
        )
    }
}

impl TcpTunnel {
    pub fn new(tid: u32, server_addr: String, key: Vec<u8>) -> Tunnel {
        let (main_sender, sub_senders, receivers) = channel_bus(10, 1000);
        let core_sender = main_sender.clone();

        task::spawn(async move {
            let duration = Duration::from_millis(HEARTBEAT_INTERVAL_MS);
            let timer_stream = timer::interval(duration, TunnelMsg::Heartbeat);
            let mut msg_stream = timer_stream.merge(receivers);

            loop {
                tcp_tunnel_core_task(
                    tid,
                    server_addr.clone(),
                    key.clone(),
                    &mut msg_stream,
                    core_sender.clone(),
                )
                .await;
            }
        });

        Tunnel {
            id: 1,
            senders: sub_senders,
            main_sender: main_sender,
        }
    }
}

impl UcpTunnel {
    pub fn new(
        tid: u32,
        server_addr: String,
        key: Vec<u8>,
        ucp_metrics: Arc<UcpStreamMetrics>,
    ) -> Tunnel {
        let (main_sender, sub_senders, receivers) = channel_bus(10, 1000);
        let core_sender = main_sender.clone();

        task::spawn(async move {
            let duration = Duration::from_millis(HEARTBEAT_INTERVAL_MS);
            let timer_stream = timer::interval(duration, TunnelMsg::Heartbeat);
            let mut msg_stream = timer_stream.merge(receivers);

            loop {
                ucp_tunnel_core_task(
                    tid,
                    server_addr.clone(),
                    key.clone(),
                    &mut msg_stream,
                    core_sender.clone(),
                    ucp_metrics.clone(),
                )
                .await;
            }
        });

        Tunnel {
            id: 1,
            senders: sub_senders,
            main_sender: main_sender,
        }
    }
}

impl TunnelWritePort {
    pub async fn write(&mut self, buf: Vec<u8>) {
        let _ = self.tx.send(TunnelMsg::CSData(self.id, buf)).await;
    }

    pub async fn connect(&mut self, buf: Vec<u8>) {
        let _ = self.tx.send(TunnelMsg::CSConnect(self.id, buf)).await;
    }

    pub async fn connect_domain_name(&mut self, buf: Vec<u8>, port: u16) {
        let _ = self
            .tx
            .send(TunnelMsg::CSConnectDN(self.id, buf, port))
            .await;
    }

    pub async fn udp_associate(&mut self, buf: Vec<u8>) {
        let _ = self.tx.send(TunnelMsg::CSUdpAssociate(self.id, buf)).await;
    }

    pub async fn shutdown_write(&mut self) {
        let _ = self.tx.send(TunnelMsg::CSShutdownWrite(self.id)).await;
    }

    pub async fn close(&mut self) {
        let _ = self.tx.send(TunnelMsg::CSClosePort(self.id)).await;
    }

    pub async fn drop(&mut self) {
        let _ = self.tx.send(TunnelMsg::TunnelPortHalfDrop(self.id)).await;
    }
}

impl TunnelReadPort {
    pub fn drain(&mut self) {
        self.rx = None;
    }

    pub async fn read(&mut self) -> TunnelPortMsg {
        match self.rx {
            Some(ref mut receiver) => match receiver.next().await {
                Some(msg) => msg,
                None => TunnelPortMsg::ClosePort,
            },

            None => TunnelPortMsg::ClosePort,
        }
    }

    pub async fn close(&mut self) {
        let _ = self.tx.send(TunnelMsg::CSClosePort(self.id)).await;
    }

    pub async fn drop(&mut self) {
        let _ = self.tx.send(TunnelMsg::TunnelPortHalfDrop(self.id)).await;
    }
}

struct Port {
    address: String,
    count: u32,
    tx: Sender<TunnelPortMsg>,
}

struct PortHub(u32, HashMap<u32, Port>);

impl PortHub {
    fn new(id: u32) -> Self {
        PortHub(id, HashMap::new())
    }

    fn get_id(&self) -> u32 {
        self.0
    }

    fn add_port(&mut self, id: u32, tx: Sender<TunnelPortMsg>) {
        self.1.insert(
            id,
            Port {
                address: String::new(),
                count: 2,
                tx: tx,
            },
        );
    }

    fn update_address(&mut self, id: u32, address: String) {
        if let Some(value) = self.1.get_mut(&id) {
            value.address = address;
        }
    }

    fn drop_port_half(&mut self, id: u32) {
        let self_id = self.get_id();

        if let Some(value) = self.1.get_mut(&id) {
            value.count = value.count - 1;
            if value.count == 0 {
                info!("{}.{}: drop tunnel port {}", self_id, id, value.address);
                self.1.remove(&id);
            }
        } else {
            info!("{}.{}: drop unknown tunnel port", self.get_id(), id);
        }
    }

    fn clear_ports(&mut self) {
        self.1.clear();
    }

    fn client_close_port(&mut self, id: u32) {
        match self.1.get(&id) {
            Some(value) => {
                info!("{}.{}: client close {}", self.get_id(), id, value.address);
                self.1.remove(&id);
            }

            None => {
                info!("{}.{}: client close unknown server", self.get_id(), id);
            }
        }
    }

    fn server_close_port(&mut self, id: u32) {
        match self.1.get(&id) {
            Some(value) => {
                info!("{}.{}: server close {}", self.get_id(), id, value.address);
                self.1.remove(&id);
            }

            None => {
                info!("{}.{}: server close unknown client", self.get_id(), id);
            }
        }
    }

    fn client_shutdown(&self, id: u32) {
        match self.1.get(&id) {
            Some(value) => {
                info!(
                    "{}.{}: client shutdown {}",
                    self.get_id(),
                    id,
                    value.address
                );
            }

            None => {
                info!("{}.{}: client shutdown unknown server", self.get_id(), id);
            }
        }
    }

    async fn server_shutdown(&mut self, id: u32) {
        match self.1.get(&id) {
            Some(value) => {
                info!(
                    "{}.{}: server shutdown write {}",
                    self.get_id(),
                    id,
                    value.address
                );
                self.try_send_msg(id, TunnelPortMsg::ShutdownWrite).await;
            }

            None => {
                info!(
                    "{}.{}: server shutdown write unknown client",
                    self.get_id(),
                    id
                );
            }
        }
    }

    async fn connect_ok(&mut self, id: u32, buf: Vec<u8>) {
        match self.1.get(&id) {
            Some(value) => {
                info!("{}.{}: connect {} ok", self.get_id(), id, value.address);
                self.try_send_msg(id, TunnelPortMsg::ConnectOk(buf)).await;
            }

            None => {
                info!("{}.{}: connect unknown server ok", self.get_id(), id);
            }
        }
    }

    async fn server_send_data(&mut self, id: u32, buf: Vec<u8>) {
        self.try_send_msg(id, TunnelPortMsg::Data(buf)).await;
    }

    async fn try_send_msg(&mut self, id: u32, msg: TunnelPortMsg) {
        let self_id = self.get_id();

        if let Some(value) = self.1.get_mut(&id) {
            match value.tx.send(msg).await {
                Ok(_) => {}
                Err(err) => {
                    error!(
                        "{}.{}: send msg to the channel of {} error: {}",
                        self_id, id, value.address, err
                    );
                    self.1.remove(&id);
                }
            }
        }
    }
}

async fn tcp_tunnel_core_task<S: Stream<Item = TunnelMsg> + Unpin>(
    tid: u32,
    server_addr: String,
    key: Vec<u8>,
    msg_stream: &mut S,
    core_tx: Sender<TunnelMsg>,
) {
    let stream = match TcpStream::connect(&server_addr).await {
        Ok(stream) => stream,

        Err(_) => {
            task::sleep(Duration::from_millis(1000)).await;
            return;
        }
    };

    let mut port_hub = PortHub::new(tid);
    let (reader, writer) = &mut (&stream, &stream);
    let r = async {
        let _ = process_tunnel_read(key.clone(), core_tx, reader).await;
        let _ = stream.shutdown(Shutdown::Both);
    };
    let w = async {
        let _ = process_tunnel_write(key.clone(), msg_stream, &mut port_hub, writer).await;
        let _ = stream.shutdown(Shutdown::Both);
    };
    let _ = r.join(w).await;

    info!("TCP tunnel {} broken", tid);
    port_hub.clear_ports();
}

async fn ucp_tunnel_core_task<S: Stream<Item = TunnelMsg> + Unpin>(
    tid: u32,
    server_addr: String,
    key: Vec<u8>,
    msg_stream: &mut S,
    core_tx: Sender<TunnelMsg>,
    ucp_metrics: Arc<UcpStreamMetrics>,
) {
    let stream = UcpStream::connect(&server_addr, ucp_metrics).await;

    let mut port_hub = PortHub::new(tid);
    let (reader, writer) = &mut (&stream, &stream);
    let r = async {
        let _ = process_tunnel_read(key.clone(), core_tx, reader).await;
        stream.shutdown();
    };
    let w = async {
        let _ = process_tunnel_write(key.clone(), msg_stream, &mut port_hub, writer).await;
        stream.shutdown();
    };
    let _ = r.join(w).await;

    info!("UCP tunnel {} broken", tid);
    port_hub.clear_ports();
}

async fn process_tunnel_read<R: Read + Unpin>(
    key: Vec<u8>,
    mut core_tx: Sender<TunnelMsg>,
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
            let _ = core_tx.send(TunnelMsg::SCHeartbeat).await;
            continue;
        }

        let mut id = [0u8; 4];
        stream.read_exact(&mut id).await?;
        let id = u32::from_be(unsafe { *(id.as_ptr() as *const u32) });

        match op {
            sc::CLOSE_PORT => {
                let _ = core_tx.send(TunnelMsg::SCClosePort(id)).await;
            }

            sc::SHUTDOWN_WRITE => {
                let _ = core_tx.send(TunnelMsg::SCShutdownWrite(id)).await;
            }

            sc::CONNECT_OK | sc::DATA => {
                let mut len = [0u8; 4];
                stream.read_exact(&mut len).await?;
                let len = u32::from_be(unsafe { *(len.as_ptr() as *const u32) });

                let mut buf = vec![0; len as usize];
                stream.read_exact(&mut buf).await?;

                let data = decryptor.decrypt(&buf);

                if op == sc::CONNECT_OK {
                    let _ = core_tx.send(TunnelMsg::SCConnectOk(id, data)).await;
                } else {
                    let _ = core_tx.send(TunnelMsg::SCData(id, data)).await;
                }
            }

            _ => {
                error!("Tunnel recv unknow operation: {}, id: {}", op, id);
                break;
            }
        }
    }

    Ok(())
}

async fn process_tunnel_write<W: Write + Unpin, S: Stream<Item = TunnelMsg> + Unpin>(
    key: Vec<u8>,
    msg_stream: &mut S,
    port_hub: &mut PortHub,
    stream: &mut W,
) -> std::io::Result<()> {
    let mut encryptor = Cryptor::new(&key);
    let mut alive_time = Instant::now();

    stream.write_all(encryptor.ctr_as_slice()).await?;
    stream.write_all(&encryptor.encrypt(&VERIFY_DATA)).await?;

    loop {
        match msg_stream.next().await {
            Some(TunnelMsg::Heartbeat) => {
                let now = Instant::now();
                let duration = now - alive_time;
                if duration.as_millis() > ALIVE_TIMEOUT_TIME_MS {
                    error!("Tunnel heartbeat timeout: {:?} - {:?}", alive_time, now);
                    break;
                }

                stream.write_all(&pack_cs_heartbeat_msg()).await?;
            }

            Some(msg) => {
                process_tunnel_msg(msg, &mut alive_time, port_hub, &mut encryptor, stream).await?;
            }

            None => {
                error!("Tunnel get none from message stream");
                break;
            }
        }
    }

    Ok(())
}

async fn process_tunnel_msg<W: Write + Unpin>(
    msg: TunnelMsg,
    alive_time: &mut Instant,
    port_hub: &mut PortHub,
    encryptor: &mut Cryptor,
    stream: &mut W,
) -> std::io::Result<()> {
    match msg {
        TunnelMsg::CSOpenPort(id, tx) => {
            info!("{}.{}: open port", port_hub.get_id(), id);
            port_hub.add_port(id, tx);
            stream.write_all(&pack_cs_open_port_msg(id)).await?;
        }

        TunnelMsg::CSConnect(id, buf) => {
            let address = String::from_utf8(buf.clone()).unwrap_or(String::new());
            info!("{}.{}: connecting {}", port_hub.get_id(), id, address);

            port_hub.update_address(id, address);

            let data = encryptor.encrypt(&buf);
            stream.write_all(&pack_cs_connect_msg(id, &data)).await?;
        }

        TunnelMsg::CSConnectDN(id, buf, port) => {
            let host = String::from_utf8(buf.clone()).unwrap_or(String::new());
            let address = format!("{}:{}", host, port);
            info!("{}.{}: connecting {}", port_hub.get_id(), id, address);

            port_hub.update_address(id, address);

            let data = encryptor.encrypt(&buf);
            let packed_buffer = pack_cs_connect_domain_msg(id, &data, port);
            stream.write_all(&packed_buffer).await?;
        }

        TunnelMsg::CSUdpAssociate(id, buf) => {
            let address = String::from_utf8(buf.clone()).unwrap_or(String::new());
            info!("{}.{}: udp associate {}", port_hub.get_id(), id, address);

            port_hub.update_address(id, address);

            let data = encryptor.encrypt(&buf);
            stream.write_all(&pack_udp_associate_msg(id, &data)).await?;
        }

        TunnelMsg::CSShutdownWrite(id) => {
            info!("{}.{}: shutdown write", port_hub.get_id(), id);
            port_hub.client_shutdown(id);
            stream.write_all(&pack_cs_shutdown_write_msg(id)).await?;
        }

        TunnelMsg::CSData(id, buf) => {
            debug!("{}.{} send {} bytes", port_hub.get_id(), id, buf.len());
            let data = encryptor.encrypt(&buf);
            stream.write_all(&pack_cs_data_msg(id, &data)).await?;
        }

        TunnelMsg::CSClosePort(id) => {
            info!("{}.{}: close port", port_hub.get_id(), id);
            port_hub.client_close_port(id);
            stream.write_all(&pack_cs_close_port_msg(id)).await?;
        }

        TunnelMsg::SCHeartbeat => {
            *alive_time = Instant::now();
        }

        TunnelMsg::SCClosePort(id) => {
            info!("{}.{}: server close port", port_hub.get_id(), id);
            *alive_time = Instant::now();
            port_hub.server_close_port(id);
        }

        TunnelMsg::SCShutdownWrite(id) => {
            info!("{}.{}: server shutdown write", port_hub.get_id(), id);
            *alive_time = Instant::now();
            port_hub.server_shutdown(id).await;
        }

        TunnelMsg::SCConnectOk(id, buf) => {
            info!("{}.{}: server connect ok", port_hub.get_id(), id);
            *alive_time = Instant::now();
            port_hub.connect_ok(id, buf).await;
        }

        TunnelMsg::SCData(id, buf) => {
            debug!("{}.{}: recv {} bytes", port_hub.get_id(), id, buf.len());
            *alive_time = Instant::now();
            port_hub.server_send_data(id, buf).await;
        }

        TunnelMsg::TunnelPortHalfDrop(id) => {
            info!("{}.{}: half drop port", port_hub.get_id(), id);
            port_hub.drop_port_half(id);
        }

        _ => {
            error!("{}: unknown message", port_hub.get_id());
        }
    }

    Ok(())
}
