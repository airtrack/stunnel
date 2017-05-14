use std::thread;
use std::cell::RefCell;
use std::collections::HashMap;
use std::net::TcpStream;
use std::time::Duration;
use std::rc::Rc;
use std::vec::Vec;
use std::sync::mpsc::{
    sync_channel, channel,
    SyncSender, Sender, Receiver
};

use time;
use super::timer::Timer;
use super::cryptor::Cryptor;
use super::ucp::{UcpClient, UcpStream};
use super::tcp::{Tcp, TcpError};
use super::protocol;
use super::protocol::{
    VERIFY_DATA, cs, sc,
    HEARTBEAT_INTERVAL_MS,
    ALIVE_TIMEOUT_TIME_MS
};

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
    core_tx: SyncSender<TunnelMsg>,
}

pub struct UcpTunnel {
    id: u32,
    core_tx: SyncSender<TunnelMsg>,
}

pub struct TunnelWritePort {
    id: u32,
    tx: SyncSender<TunnelMsg>,
}

pub struct TunnelReadPort {
    id: u32,
    tx: SyncSender<TunnelMsg>,
    rx: Receiver<TunnelPortMsg>,
}

struct TunnelError;

struct PortMapValue {
    host: String,
    port: u16,
    count: u32,
    tx: Sender<TunnelPortMsg>,
}

type PortMap = HashMap<u32, PortMapValue>;

impl Tunnel {
    pub fn new(tid: u32, server_addr: String, key: Vec<u8>) -> Tunnel {
        let (tx, rx) = sync_channel(10000);
        let tx2 = tx.clone();

        thread::spawn(move || {
            tunnel_core_task(tid, server_addr, key, rx, tx);
        });

        Tunnel { id: 1, core_tx: tx2 }
    }

    pub fn open_port(&mut self) -> (TunnelWritePort, TunnelReadPort) {
        let core_tx1 = self.core_tx.clone();
        let core_tx2 = self.core_tx.clone();
        let id = self.id;
        self.id += 1;

        let (tx, rx) = channel();
        let _ = self.core_tx.send(TunnelMsg::CSOpenPort(id, tx));

        (TunnelWritePort { id: id, tx: core_tx1 },
         TunnelReadPort { id: id, tx: core_tx2, rx: rx })
    }
}

impl UcpTunnel {
    pub fn new(tid: u32, server_addr: String, key: Vec<u8>) -> UcpTunnel {
        let (tx, rx) = sync_channel(10000);
        let tx2 = tx.clone();

        thread::spawn(move || {
            ucp_tunnel_core_task(tid, server_addr, key,
                                 Rc::new(rx), Rc::new(tx));
        });

        UcpTunnel { id: 1, core_tx: tx2 }
    }

    pub fn open_port(&mut self) -> (TunnelWritePort, TunnelReadPort) {
        let core_tx1 = self.core_tx.clone();
        let core_tx2 = self.core_tx.clone();
        let id = self.id;
        self.id += 1;

        let (tx, rx) = channel();
        let _ = self.core_tx.send(TunnelMsg::CSOpenPort(id, tx));

        (TunnelWritePort { id: id, tx: core_tx1 },
         TunnelReadPort { id: id, tx: core_tx2, rx: rx })
    }
}

impl TunnelWritePort {
    pub fn write(&self, buf: Vec<u8>) {
        let _ = self.tx.send(TunnelMsg::CSData(self.id, buf));
    }

    pub fn connect(&self, buf: Vec<u8>) {
        let _ = self.tx.send(TunnelMsg::CSConnect(self.id, buf));
    }

    pub fn connect_domain_name(&self, buf: Vec<u8>, port: u16) {
        let _ = self.tx.send(TunnelMsg::CSConnectDN(self.id, buf, port));
    }

    pub fn shutdown_write(&self) {
        let _ = self.tx.send(TunnelMsg::CSShutdownWrite(self.id));
    }

    pub fn close(&self) {
        let _ = self.tx.send(TunnelMsg::CSClosePort(self.id));
    }
}

impl Drop for TunnelWritePort {
    fn drop(&mut self) {
        let _ = self.tx.send(TunnelMsg::TunnelPortDrop(self.id));
    }
}

impl TunnelReadPort {
    pub fn read(&self) -> TunnelPortMsg {
        match self.rx.recv() {
            Ok(msg) => msg,
            Err(_) => TunnelPortMsg::ClosePort
        }
    }
}

impl Drop for TunnelReadPort {
    fn drop(&mut self) {
        let _ = self.tx.send(TunnelMsg::TunnelPortDrop(self.id));
    }
}

fn tunnel_tcp_recv(key: Vec<u8>, receiver: TcpStream,
                   core_tx: SyncSender<TunnelMsg>) {
    let mut stream = Tcp::new(receiver);
    let _ = tunnel_recv_loop(&key, &core_tx, &mut stream);
    stream.shutdown();
}

fn tunnel_recv_loop(key: &Vec<u8>, core_tx: &SyncSender<TunnelMsg>,
                    stream: &mut Tcp) -> Result<(), TcpError> {
    let ctr = try!(stream.read_exact(Cryptor::ctr_size()));
    let mut decryptor = Cryptor::with_ctr(&key[..], ctr);

    loop {
        let op = try!(stream.read_u8());
        if op == sc::HEARTBEAT_RSP {
            let _ = core_tx.send(TunnelMsg::SCHeartbeat);
            continue
        }

        let id = try!(stream.read_u32());
        match op {
            sc::CLOSE_PORT => {
                let _ = core_tx.send(TunnelMsg::SCClosePort(id));
            },

            sc::SHUTDOWN_WRITE => {
                let _ = core_tx.send(TunnelMsg::SCShutdownWrite(id));
            },

            sc::CONNECT_OK => {
                let len = try!(stream.read_u32());
                let buf = try!(stream.read_exact(len as usize));
                let data = decryptor.decrypt(&buf[..]);
                let _ = core_tx.send(TunnelMsg::SCConnectOk(id, data));
            },

            sc::DATA => {
                let len = try!(stream.read_u32());
                let buf = try!(stream.read_exact(len as usize));
                let data = decryptor.decrypt(&buf[..]);
                let _ = core_tx.send(TunnelMsg::SCData(id, data));
            },

            _ => break
        }
    }

    Ok(())
}

struct UcpTask {
    core_rx: Rc<Receiver<TunnelMsg>>,
    port_map: Rc<RefCell<PortMap>>,
    encryptor: Cryptor,
    decryptor: Cryptor,
    tid: u32
}

impl UcpTask {
    fn new(tid: u32, key: &[u8], core_rx: Rc<Receiver<TunnelMsg>>,
           port_map: Rc<RefCell<PortMap>>) -> UcpTask {
        let encryptor = Cryptor::new(key);
        let decryptor = Cryptor::new(key);

        UcpTask {
            core_rx: core_rx, port_map: port_map,
            encryptor: encryptor, decryptor: decryptor, tid: tid
        }
    }

    fn update(&mut self, ucp: &mut UcpStream) -> bool {
        self.process_tunnel_msg(ucp);
        true
    }

    fn process_tunnel_msg(&mut self, ucp: &mut UcpStream) {
        if let Ok(msg) = self.core_rx.try_recv() {
            let mut time = time::get_time();
            let _ = process_tunnel_msg(
                self.tid, msg, &mut time, &mut *self.port_map.borrow_mut(),
                &mut self.encryptor, |buf| { ucp.send(buf); Ok(()) });
        }
    }
}

fn ucp_tunnel_core_task(tid: u32, server_addr: String, key: Vec<u8>,
                        core_rx: Rc<Receiver<TunnelMsg>>,
                        core_tx: Rc<SyncSender<TunnelMsg>>) {
    loop {
        let mut ucp_client = UcpClient::connect(&server_addr[..]);
        let port_map = Rc::new(RefCell::new(PortMap::new()));
        let mut ucp_task = UcpTask::new(
            tid, &key[..], core_rx.clone(), port_map.clone());

        ucp_client.set_on_update(move |ucp| { ucp_task.update(ucp) });
        ucp_client.set_on_broken(|| {});
        ucp_client.run();

        info!("tunnel {} broken", tid);
        for (_, value) in port_map.borrow().iter() {
            let _ = value.tx.send(TunnelPortMsg::ClosePort);
        }
    }
}

fn tunnel_core_task(tid: u32, server_addr: String, key: Vec<u8>,
                    core_rx: Receiver<TunnelMsg>,
                    core_tx: SyncSender<TunnelMsg>) {
    let sender = match TcpStream::connect(&server_addr[..]) {
        Ok(sender) => sender,
        Err(_) => {
            thread::sleep(Duration::from_millis(1000));
            thread::spawn(move || {
                tunnel_core_task(tid, server_addr, key, core_rx, core_tx);
            });
            return
        }
    };

    let receiver = sender.try_clone().unwrap();
    let core_tx2 = core_tx.clone();
    let key2 = key.clone();

    thread::spawn(move || {
        tunnel_tcp_recv(key2, receiver, core_tx2);
    });

    let mut stream = Tcp::new(sender);
    let mut port_map = PortMap::new();

    let _ = tunnel_loop(tid, &key, &core_rx, &mut stream, &mut port_map);
    info!("tunnel {} broken", tid);

    stream.shutdown();
    for (_, value) in port_map.iter() {
        let _ = value.tx.send(TunnelPortMsg::ClosePort);
    }

    thread::spawn(move || {
        tunnel_core_task(tid, server_addr, key, core_rx, core_tx);
    });
}

fn tunnel_loop(tid: u32, key: &Vec<u8>,
               core_rx: &Receiver<TunnelMsg>, stream: &mut Tcp,
               port_map: &mut PortMap)
    -> Result<(), TunnelError> {
    let mut encryptor = Cryptor::new(&key[..]);
    let mut alive_time = time::get_time();
    let timer = Timer::new(HEARTBEAT_INTERVAL_MS);

    try!(stream.write(encryptor.ctr_as_slice())
         .map_err(|_| TunnelError {}));
    try!(stream.write(&encryptor.encrypt(&VERIFY_DATA)[..])
         .map_err(|_| TunnelError {}));

    loop {
        select! {
            _ = timer.recv() => {
                let duration = time::get_time() - alive_time;
                if duration.num_milliseconds() > ALIVE_TIMEOUT_TIME_MS {
                    break
                }
                try!(stream.write_u8(cs::HEARTBEAT)
                     .map_err(|_| TunnelError {}));
            },

            msg = core_rx.recv() => {
                try!(process_tunnel_msg(
                        tid, msg.unwrap(), &mut alive_time,
                        port_map, &mut encryptor,
                        |buf| stream.write(buf).map_err(|_| TunnelError {})));
            }
        }
    }

    Ok(())
}

fn process_tunnel_msg<F>(tid: u32, msg: TunnelMsg,
                         alive_time: &mut time::Timespec,
                         port_map: &mut PortMap,
                         encryptor: &mut Cryptor,
                         send: F)
    -> Result<(), TunnelError>
    where F: FnOnce(&[u8]) -> Result<(), TunnelError> {
    match msg {
        TunnelMsg::CSOpenPort(id, tx) => {
            port_map.insert(id, PortMapValue {
                count: 2, tx: tx, host: String::new(), port: 0 });

            try!(send(&protocol::pack_cs_open_port_msg(id)));
        },

        TunnelMsg::CSConnect(id, buf) => {
            let data = encryptor.encrypt(&buf[..]);
            try!(send(&protocol::pack_cs_connect_msg(id, &data[..])[..]));
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
                protocol::pack_cs_connect_domain_msg(id, &data[..], port);
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

            try!(send(&protocol::pack_cs_shutdown_write_msg(id)));
        },

        TunnelMsg::CSData(id, buf) => {
            let data = encryptor.encrypt(&buf[..]);

            try!(send(&protocol::pack_cs_data_msg(id, &data[..])[..]));
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
                let _ = value.tx.send(TunnelPortMsg::ClosePort);

                try!(send(&protocol::pack_cs_close_port_msg(id)));
                Ok(())
            });

            match res {
                Some(Err(e)) => return Err(e),
                _ => {}
            }

            port_map.remove(&id);
        },

        TunnelMsg::SCHeartbeat => {
            *alive_time = time::get_time();
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

            *alive_time = time::get_time();
            port_map.get(&id).map(|value| {
                let _ = value.tx.send(TunnelPortMsg::ClosePort);
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

            *alive_time = time::get_time();
            port_map.get(&id).map(|value| {
                let _ = value.tx.send(TunnelPortMsg::ShutdownWrite);
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

            *alive_time = time::get_time();
            port_map.get(&id).map(move |value| {
                let _ = value.tx.send(TunnelPortMsg::ConnectOk(buf));
            });
        },

        TunnelMsg::SCData(id, buf) => {
            *alive_time = time::get_time();
            port_map.get(&id).map(move |value| {
                let _ = value.tx.send(TunnelPortMsg::Data(buf));
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
