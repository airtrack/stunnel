use std::thread;
use std::cell::RefCell;
use std::collections::HashMap;
use std::net::TcpStream;
use std::time::Duration;
use std::rc::Rc;
use std::vec::Vec;

use crossbeam_channel::select;
use crossbeam_channel::{Sender, Receiver};
use crossbeam_channel as channel;

use time::{get_time, Timespec};
use super::timer::Timer;
use super::ucp::{UcpClient, UcpStream};
use super::tcp::{Tcp, TcpError};
use super::cryptor::*;
use super::protocol::*;

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
    pub fn open_port(&mut self) -> (TunnelWritePort, TunnelReadPort) {
        let core_tx1 = self.core_tx.clone();
        let core_tx2 = self.core_tx.clone();
        let id = self.id;
        self.id += 1;

        let (tx, rx) = channel::unbounded();
        self.core_tx.send(TunnelMsg::CSOpenPort(id, tx));

        (TunnelWritePort { id: id, tx: core_tx1 },
         TunnelReadPort { id: id, tx: core_tx2, rx: rx })
    }
}

impl TcpTunnel {
    pub fn new(tid: u32, server_addr: String, key: Vec<u8>) -> Tunnel {
        let (tx, rx) = channel::bounded(10000);
        let tx2 = tx.clone();

        thread::spawn(move || {
            tcp_tunnel_core_task(tid, server_addr, key, rx, tx);
        });

        Tunnel { id: 1, core_tx: tx2 }
    }
}

impl UcpTunnel {
    pub fn new(tid: u32, server_addr: String, key: Vec<u8>) -> Tunnel {
        let (tx, rx) = channel::bounded(10000);

        thread::spawn(move || {
            ucp_tunnel_core_task(tid, server_addr, key, Rc::new(rx));
        });

        Tunnel { id: 1, core_tx: tx }
    }
}

impl TunnelWritePort {
    pub fn write(&self, buf: Vec<u8>) {
        self.tx.send(TunnelMsg::CSData(self.id, buf));
    }

    pub fn connect(&self, buf: Vec<u8>) {
        self.tx.send(TunnelMsg::CSConnect(self.id, buf));
    }

    pub fn connect_domain_name(&self, buf: Vec<u8>, port: u16) {
        self.tx.send(TunnelMsg::CSConnectDN(self.id, buf, port));
    }

    pub fn shutdown_write(&self) {
        self.tx.send(TunnelMsg::CSShutdownWrite(self.id));
    }

    pub fn close(&self) {
        self.tx.send(TunnelMsg::CSClosePort(self.id));
    }
}

impl Drop for TunnelWritePort {
    fn drop(&mut self) {
        self.tx.send(TunnelMsg::TunnelPortDrop(self.id));
    }
}

impl TunnelReadPort {
    pub fn read(&self) -> TunnelPortMsg {
        match self.rx.recv() {
            Some(msg) => msg,
            None => TunnelPortMsg::ClosePort
        }
    }
}

impl Drop for TunnelReadPort {
    fn drop(&mut self) {
        self.tx.send(TunnelMsg::TunnelPortDrop(self.id));
    }
}

struct TunnelError;

struct PortMapValue {
    host: String,
    port: u16,
    count: u32,
    tx: Sender<TunnelPortMsg>,
}

type PortMap = HashMap<u32, PortMapValue>;

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

fn tcp_tunnel_core_task(tid: u32, server_addr: String, key: Vec<u8>,
                        core_rx: Receiver<TunnelMsg>,
                        core_tx: Sender<TunnelMsg>) {
    let sender = match TcpStream::connect(&server_addr[..]) {
        Ok(sender) => sender,
        Err(_) => {
            thread::sleep(Duration::from_millis(1000));
            thread::spawn(move || {
                tcp_tunnel_core_task(tid, server_addr, key, core_rx, core_tx);
            });
            return
        }
    };

    let receiver = sender.try_clone().unwrap();
    let core_tx2 = core_tx.clone();
    let key2 = key.clone();

    thread::spawn(move || {
        tcp_tunnel_recv_task(key2, receiver, core_tx2);
    });

    let mut stream = Tcp::new(sender);
    let mut port_map = PortMap::new();

    let _ = tcp_tunnel_loop(tid, &key, &core_rx, &mut stream, &mut port_map);
    info!("tunnel {} broken", tid);

    stream.shutdown();
    for (_, value) in port_map.iter() {
        value.tx.send(TunnelPortMsg::ClosePort);
    }

    thread::spawn(move || {
        tcp_tunnel_core_task(tid, server_addr, key, core_rx, core_tx);
    });
}

fn tcp_tunnel_loop(tid: u32, key: &Vec<u8>,
                   core_rx: &Receiver<TunnelMsg>, stream: &mut Tcp,
                   port_map: &mut PortMap)
    -> Result<(), TunnelError> {
    let mut encryptor = Cryptor::new(&key[..]);
    let mut alive_time = get_time();
    let timer = Timer::new(HEARTBEAT_INTERVAL_MS as u32);

    try!(stream.write(encryptor.ctr_as_slice())
         .map_err(|_| TunnelError {}));
    try!(stream.write(&encryptor.encrypt(&VERIFY_DATA)[..])
         .map_err(|_| TunnelError {}));

    loop {
        select! {
            recv(timer, _) => {
                let duration = get_time() - alive_time;
                if duration.num_milliseconds() > ALIVE_TIMEOUT_TIME_MS {
                    break
                }
                try!(stream.write(&pack_cs_heartbeat_msg())
                     .map_err(|_| TunnelError {}));
            },

            recv(core_rx, msg) => match msg {
                Some(msg) => {
                    try!(process_tunnel_msg(
                        tid, msg, &mut alive_time,
                        port_map, &mut encryptor,
                        |buf| stream.write(buf).map_err(|_| TunnelError {})));
                },
                None => break
            }
        }
    }

    Ok(())
}

fn tcp_tunnel_recv_task(key: Vec<u8>, receiver: TcpStream,
                        core_tx: Sender<TunnelMsg>) {
    let mut stream = Tcp::new(receiver);
    let _ = tcp_tunnel_recv_loop(&key, &core_tx, &mut stream);
    stream.shutdown();
}

fn tcp_tunnel_recv_loop(key: &Vec<u8>, core_tx: &Sender<TunnelMsg>,
                        stream: &mut Tcp) -> Result<(), TcpError> {
    let ctr = try!(stream.read_exact(CTR_SIZE));
    let mut decryptor = Cryptor::with_ctr(&key[..], ctr);

    loop {
        let op = try!(stream.read_u8());
        if op == sc::HEARTBEAT_RSP {
            core_tx.send(TunnelMsg::SCHeartbeat);
            continue
        }

        let id = try!(stream.read_u32());
        match op {
            sc::CLOSE_PORT => {
                core_tx.send(TunnelMsg::SCClosePort(id));
            },

            sc::SHUTDOWN_WRITE => {
                core_tx.send(TunnelMsg::SCShutdownWrite(id));
            },

            sc::CONNECT_OK => {
                let len = try!(stream.read_u32());
                let buf = try!(stream.read_exact(len as usize));
                let data = decryptor.decrypt(&buf[..]);
                core_tx.send(TunnelMsg::SCConnectOk(id, data));
            },

            sc::DATA => {
                let len = try!(stream.read_u32());
                let buf = try!(stream.read_exact(len as usize));
                let data = decryptor.decrypt(&buf[..]);
                core_tx.send(TunnelMsg::SCData(id, data));
            },

            _ => break
        }
    }

    Ok(())
}

fn process_tunnel_msg<F>(tid: u32, msg: TunnelMsg,
                         alive_time: &mut Timespec,
                         port_map: &mut PortMap,
                         encryptor: &mut Cryptor,
                         send: F)
    -> Result<(), TunnelError>
    where F: FnOnce(&[u8]) -> Result<(), TunnelError> {
    match msg {
        TunnelMsg::CSOpenPort(id, tx) => {
            port_map.insert(id, PortMapValue {
                count: 2, tx: tx, host: String::new(), port: 0 });

            try!(send(&pack_cs_open_port_msg(id)));
        },

        TunnelMsg::CSConnect(id, buf) => {
            let data = encryptor.encrypt(&buf[..]);
            try!(send(&pack_cs_connect_msg(id, &data[..])[..]));
        },

        TunnelMsg::CSConnectDN(id, buf, port) => {
            let host = String::from_utf8(buf.clone()).
                unwrap_or(String::new());

            if let Some(value) = port_map.get_mut(&id) {
                value.host = host.clone();
                value.port = port;
            }

            info!("{}.{}: connecting {}:{}", tid, id, host, port);

            let data = encryptor.encrypt(&buf[..]);

            let packed_buffer =
                pack_cs_connect_domain_msg(id, &data[..], port);
            try!(send(&packed_buffer[..]));
        },

        TunnelMsg::CSShutdownWrite(id) => {
            match port_map.get(&id) {
                Some(value) => {
                    info!("{}.{}: client shutdown write {}:{}",
                          tid, id, value.host, value.port);
                },
                None => {
                    info!("{}.{}: client shutdown write unknown server",
                          tid, id);
                }
            }

            try!(send(&pack_cs_shutdown_write_msg(id)));
        },

        TunnelMsg::CSData(id, buf) => {
            let data = encryptor.encrypt(&buf[..]);

            try!(send(&pack_cs_data_msg(id, &data[..])[..]));
        },

        TunnelMsg::CSClosePort(id) => {
            match port_map.get(&id) {
                Some(value) => {
                    info!("{}.{}: client close {}:{}",
                          tid, id, value.host, value.port);
                },
                None => {
                    info!("{}.{}: client close unknown server",
                          tid, id);
                }
            }

            let res = port_map.get(&id).map(|value| {
                value.tx.send(TunnelPortMsg::ClosePort);

                try!(send(&pack_cs_close_port_msg(id)));
                Ok(())
            });

            match res {
                Some(Err(e)) => return Err(e),
                _ => {}
            }

            port_map.remove(&id);
        },

        TunnelMsg::SCHeartbeat => {
            *alive_time = get_time();
        },

        TunnelMsg::SCClosePort(id) => {
            match port_map.get(&id) {
                Some(value) => {
                    info!("{}.{}: server close {}:{}",
                          tid, id, value.host, value.port);
                },
                None => {
                    info!("{}.{}: server close unknown client",
                          tid, id);
                }
            }

            *alive_time = get_time();
            port_map.get(&id).map(|value| {
                value.tx.send(TunnelPortMsg::ClosePort);
            });

            port_map.remove(&id);
        },

        TunnelMsg::SCShutdownWrite(id) => {
            match port_map.get(&id) {
                Some(value) => {
                    info!("{}.{}: server shutdown write {}:{}",
                          tid, id, value.host, value.port);
                },
                None => {
                    info!("{}.{}: server shutdown write unknown client",
                          tid, id);
                }
            }

            *alive_time = get_time();
            port_map.get(&id).map(|value| {
                value.tx.send(TunnelPortMsg::ShutdownWrite);
            });
        },

        TunnelMsg::SCConnectOk(id, buf) => {
            match port_map.get(&id) {
                Some(value) => {
                    info!("{}.{}: connect {}:{} ok",
                          tid, id, value.host, value.port);
                },
                None => {
                    info!("{}.{}: connect unknown server ok",
                          tid, id);
                }
            }

            *alive_time = get_time();
            port_map.get(&id).map(move |value| {
                value.tx.send(TunnelPortMsg::ConnectOk(buf));
            });
        },

        TunnelMsg::SCData(id, buf) => {
            *alive_time = get_time();
            port_map.get(&id).map(move |value| {
                value.tx.send(TunnelPortMsg::Data(buf));
            });
        },

        TunnelMsg::TunnelPortDrop(id) => {
            let remove = if let Some(value)
                = port_map.get_mut(&id) {
                    value.count = value.count - 1;
                    value.count == 0
                } else {
                    false
                };

            if remove {
                match port_map.get(&id) {
                    Some(value) => {
                        info!("{}.{}: drop tunnel port {}:{}",
                              tid, id, value.host, value.port);
                    },
                    None => {
                        info!("{}.{}: drop unknown tunnel port",
                              tid, id);
                    }
                }

                port_map.remove(&id);
            }
        }
    }

    Ok(())
}
