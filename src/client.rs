use std::sync::mpsc::channel;
use std::sync::mpsc::Sender;
use std::sync::mpsc::Receiver;
use std::thread;
use std::collections::HashMap;
use std::net::TcpStream;
use std::vec::Vec;
use time;
use super::tcp::Tcp;
use super::timer::Timer;
use super::cryptor::Cryptor;
use super::protocol::{
    VERIFY_DATA, cs, sc,
    HEARTBEAT_INTERVAL_MS,
    ALIVE_TIMEOUT_TIME_MS
};

enum TunnelMsg {
    Heartbeat,
    OpenPort(u32, Sender<TunnelPortMsg>),
    ClosePort(u32),
    Shutdown(u32),
    Connect(u32, Vec<u8>),
    ConnectDN(u32, Vec<u8>, u16),
    ConnectOk(u32, Vec<u8>),
    RecvData(u32, Vec<u8>),
    SendData(u32, Vec<u8>),
}

pub enum TunnelPortMsg {
    ConnectOk(Vec<u8>),
    Data(Vec<u8>),
    ClosePort,
}

pub struct Tunnel {
    id: u32,
    core_tx: Sender<TunnelMsg>,
}

pub struct TunnelWritePort {
    id: u32,
    tx: Sender<TunnelMsg>,
}

pub struct TunnelReadPort {
    rx: Receiver<TunnelPortMsg>,
}

impl Tunnel {
    pub fn new(server_addr: String, key: Vec<u8>) -> Tunnel {
        let (tx, rx) = channel();
        let tx2 = tx.clone();

        thread::spawn(move || {
            tunnel_core_task(server_addr, key, rx, tx);
        });

        Tunnel { id: 1, core_tx: tx2 }
    }

    pub fn open_port(&mut self) -> (TunnelWritePort, TunnelReadPort) {
        let core_tx = self.core_tx.clone();
        let id = self.id;
        self.id += 1;

        let (tx, rx) = channel();
        let _ = self.core_tx.send(TunnelMsg::OpenPort(id, tx));

        (TunnelWritePort { id: id, tx: core_tx }, TunnelReadPort { rx: rx })
    }
}

impl TunnelWritePort {
    pub fn write(&mut self, buf: Vec<u8>) {
        let _ = self.tx.send(TunnelMsg::SendData(self.id, buf));
    }

    pub fn connect(&mut self, buf: Vec<u8>) {
        let _ = self.tx.send(TunnelMsg::Connect(self.id, buf));
    }

    pub fn connect_domain_name(&mut self, buf: Vec<u8>, port: u16) {
        let _ = self.tx.send(TunnelMsg::ConnectDN(self.id, buf, port));
    }

    pub fn close(&mut self) {
        let _ = self.tx.send(TunnelMsg::ClosePort(self.id));
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

fn tunnel_tcp_recv(key: Vec<u8>, receiver: TcpStream,
                   core_tx: Sender<TunnelMsg>) {
    let mut stream = Tcp::new(receiver);
    let ctr = stream.read_exact(Cryptor::ctr_size());
    if ctr.len() == 0 {
        stream.shutdown();
        return
    }

    let mut decryptor = Cryptor::with_ctr(&key[..], ctr);

    loop {
        let op = match stream.read_u8() {
            Some(op) => op,
            None => break
        };

        if op == sc::HEARTBEAT_RSP {
            let _ = core_tx.send(TunnelMsg::Heartbeat);
            continue
        }

        let id = match stream.read_u32() {
            Some(id) => id,
            None => break
        };

        match op {
            sc::CONNECT_OK => {
                let len = match stream.read_u32() {
                    Some(len) => len,
                    None => break
                };

                let buf = stream.read_exact(len as usize);
                if buf.len() == 0 {
                    break
                }

                let data = decryptor.decrypt(&buf[..]);
                let _ = core_tx.send(TunnelMsg::ConnectOk(id, data));
            },

            sc::SHUTDOWN => {
                let _ = core_tx.send(TunnelMsg::Shutdown(id));
            },

            sc::DATA => {
                let len = match stream.read_u32() {
                    Some(len) => len,
                    None => break
                };

                let buf = stream.read_exact(len as usize);
                if buf.len() == 0 {
                    break
                }

                let data = decryptor.decrypt(&buf[..]);
                let _ = core_tx.send(TunnelMsg::RecvData(id, data));
            },

            _ => break
        }
    }

    stream.shutdown();
}

fn tunnel_core_task(server_addr: String, key: Vec<u8>,
                    core_rx: Receiver<TunnelMsg>,
                    core_tx: Sender<TunnelMsg>) {
    let sender = match TcpStream::connect(&server_addr[..]) {
        Ok(sender) => sender,
        Err(_) => {
            thread::sleep_ms(1000);
            thread::spawn(move || {
                tunnel_core_task(server_addr, key, core_rx, core_tx);
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
    let mut encryptor = Cryptor::new(&key[..]);
    stream.write(encryptor.ctr_as_slice());
    stream.write(&encryptor.encrypt(&VERIFY_DATA)[..]);

    let timer = Timer::new(HEARTBEAT_INTERVAL_MS);
    let mut alive_time = time::get_time();

    let mut port_map = HashMap::new();
    loop {
        select! {
            _ = timer.recv() => {
                let duration = time::get_time() - alive_time;
                if duration.num_milliseconds() > ALIVE_TIMEOUT_TIME_MS {
                    break
                }
                if !stream.write_u8(cs::HEARTBEAT) { break }
            },

            msg = core_rx.recv() => match msg.unwrap() {
                TunnelMsg::Heartbeat => {
                    alive_time = time::get_time();
                },

                TunnelMsg::OpenPort(id, tx) => {
                    port_map.insert(id, tx);

                    if !stream.write_u8(cs::OPEN_PORT) { break }
                    if !stream.write_u32(id) { break }
                },

                TunnelMsg::ClosePort(id) => {
                    let res = port_map.get(&id).map(|tx| {
                        let _ = tx.send(TunnelPortMsg::ClosePort);

                        if !stream.write_u8(cs::CLOSE_PORT) { return false }
                        if !stream.write_u32(id) { return false }
                        true
                    });

                    match res {
                        Some(false) => break,
                        _ => {}
                    }

                    port_map.remove(&id);
                },

                TunnelMsg::Shutdown(id) => {
                    port_map.get(&id).map(|tx| {
                        let _ = tx.send(TunnelPortMsg::ClosePort);
                    });

                    port_map.remove(&id);
                },

                TunnelMsg::Connect(id, buf) => {
                    let data = encryptor.encrypt(&buf[..]);

                    if !stream.write_u8(cs::CONNECT) { break }
                    if !stream.write_u32(id) { break }
                    if !stream.write_u32(data.len() as u32) { break }
                    if !stream.write(&data[..]) { break }
                },

                TunnelMsg::ConnectDN(id, buf, port) => {
                    let data = encryptor.encrypt(&buf[..]);

                    if !stream.write_u8(cs::CONNECT_DOMAIN_NAME) { break }
                    if !stream.write_u32(id) { break }
                    if !stream.write_u32(data.len() as u32 + 2) { break }
                    if !stream.write(&data[..]) { break }
                    if !stream.write_u16(port) { break }
                },

                TunnelMsg::ConnectOk(id, buf) => {
                    port_map.get(&id).map(move |tx| {
                        let _ = tx.send(TunnelPortMsg::ConnectOk(buf));
                    });
                },

                TunnelMsg::RecvData(id, buf) => {
                    port_map.get(&id).map(move |tx| {
                        let _ = tx.send(TunnelPortMsg::Data(buf));
                    });
                },

                TunnelMsg::SendData(id, buf) => {
                    let data = encryptor.encrypt(&buf[..]);

                    if !stream.write_u8(cs::DATA) { break }
                    if !stream.write_u32(id) { break }
                    if !stream.write_u32(data.len() as u32) { break }
                    if !stream.write(&data[..]) { break }
                }
            }
        }
    }

    stream.shutdown();

    for (_, tx) in port_map.iter() {
        let _ = tx.send(TunnelPortMsg::ClosePort);
    }

    thread::spawn(move || {
        tunnel_core_task(server_addr, key, core_rx, core_tx);
    });
}
