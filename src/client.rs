use std::thread::Thread;
use std::collections::HashMap;
use std::io::TcpStream;
use std::vec::Vec;
use super::protocol::{cs, sc};

enum TunnelMsg {
    OpenPort(i32, Sender<TunnelPortMsg>),
    ClosePort(i32),
    Shutdown(i32),
    Connect(i32, Vec<u8>),
    ConnectDN(i32, Vec<u8>, u16),
    ConnectOk(i32, Vec<u8>),
    RecvData(i32, Vec<u8>),
    SendData(i32, Vec<u8>),
}

pub enum TunnelPortMsg {
    ConnectOk(Vec<u8>),
    Data(Vec<u8>),
    ClosePort,
}

pub struct Tunnel {
    id: i32,
    core_tx: Sender<TunnelMsg>,
}

pub struct TunnelWritePort {
    id: i32,
    tx: Sender<TunnelMsg>,
}

pub struct TunnelReadPort {
    rx: Receiver<TunnelPortMsg>,
}

impl Tunnel {
    pub fn new() -> Tunnel {
        let (tx, rx) = channel();
        let tx2 = tx.clone();
        Thread::spawn(move || {
            tunnel_core_task(rx, tx2);
        }).detach();

        Tunnel { id: 1, core_tx: tx }
    }

    pub fn open_port(&mut self) -> (TunnelWritePort, TunnelReadPort) {
        let core_tx = self.core_tx.clone();
        let id = self.id;
        self.id += 1;

        let (tx, rx) = channel();
        self.core_tx.send(TunnelMsg::OpenPort(id, tx));

        (TunnelWritePort { id: id, tx: core_tx }, TunnelReadPort { rx: rx })
    }
}

impl TunnelWritePort {
    pub fn write(&mut self, buf: Vec<u8>) {
        self.tx.send(TunnelMsg::SendData(self.id, buf));
    }

    pub fn connect(&mut self, buf: Vec<u8>) {
        self.tx.send(TunnelMsg::Connect(self.id, buf));
    }

    pub fn connect_domain_name(&mut self, buf: Vec<u8>, port: u16) {
        self.tx.send(TunnelMsg::ConnectDN(self.id, buf, port));
    }

    pub fn close(&mut self) {
        self.tx.send(TunnelMsg::ClosePort(self.id));
    }
}

impl TunnelReadPort {
    pub fn read(&self) -> TunnelPortMsg {
        self.rx.recv()
    }
}

fn tunnel_tcp_recv(mut stream: TcpStream, core_tx: Sender<TunnelMsg>) {
    loop {
        let op = match stream.read_u8() {
            Ok(op) => op,
            Err(_) => panic!("read tcp tunnel error")
        };

        let id = match stream.read_be_i32() {
            Ok(id) => id,
            Err(_) => panic!("read tcp tunnel error")
        };

        match op {
            sc::CONNECT_OK => {
                let len = match stream.read_be_uint() {
                    Ok(len) => len,
                    Err(_) => panic!("read tcp tunnel error")
                };

                match stream.read_exact(len) {
                    Ok(buf) => {
                        core_tx.send(TunnelMsg::ConnectOk(id, buf));
                    },
                    Err(_) => panic!("read tcp tunnel error")
                }
            },
            sc::SHUTDOWN => {
                core_tx.send(TunnelMsg::Shutdown(id));
            },
            sc::DATA => {
                let len = match stream.read_be_uint() {
                    Ok(len) => len,
                    Err(_) => panic!("read tcp tunnel error")
                };

                match stream.read_exact(len) {
                    Ok(buf) => {
                        core_tx.send(TunnelMsg::RecvData(id, buf));
                    },
                    Err(_) => panic!("read tcp tunnel error")
                }
            },
            _ => panic!("unknown op")
        }
    }
}

fn tunnel_core_task(core_rx: Receiver<TunnelMsg>, core_tx: Sender<TunnelMsg>) {
    let mut stream = TcpStream::connect("127.0.0.1:12345").unwrap();
    let receiver = stream.clone();
    let core_tx2 = core_tx.clone();

    Thread::spawn(move || {
        tunnel_tcp_recv(receiver, core_tx2);
    }).detach();

    let mut port_map = HashMap::new();
    loop {
        match core_rx.recv() {
            TunnelMsg::OpenPort(id, tx) => {
                port_map.insert(id, tx);

                let _ = stream.write_u8(cs::OPEN_PORT);
                let _ = stream.write_be_i32(id);
            },
            TunnelMsg::ClosePort(id) => {
                port_map.get(&id).map(|tx| {
                    let _ = tx.send_opt(TunnelPortMsg::ClosePort);

                    let _ = stream.write_u8(cs::CLOSE_PORT);
                    let _ = stream.write_be_i32(id);
                });

                port_map.remove(&id);
            },
            TunnelMsg::Shutdown(id) => {
                port_map.get(&id).map(|tx| {
                    let _ = tx.send_opt(TunnelPortMsg::ClosePort);
                });

                port_map.remove(&id);
            },
            TunnelMsg::Connect(id, buf) => {
                let _ = stream.write_u8(cs::CONNECT);
                let _ = stream.write_be_i32(id);
                let _ = stream.write_be_uint(buf.len());
                let _ = stream.write(buf.as_slice());
            },
            TunnelMsg::ConnectDN(id, buf, port) => {
                let _ = stream.write_u8(cs::CONNECT_DOMAIN_NAME);
                let _ = stream.write_be_i32(id);
                let _ = stream.write_be_uint(buf.len() + 2);
                let _ = stream.write(buf.as_slice());
                let _ = stream.write_be_u16(port);
            },
            TunnelMsg::ConnectOk(id, buf) => {
                port_map.get(&id).map(move |tx| {
                    let _ = tx.send_opt(TunnelPortMsg::ConnectOk(buf));
                });
            },
            TunnelMsg::RecvData(id, buf) => {
                port_map.get(&id).map(move |tx| {
                    let _ = tx.send_opt(TunnelPortMsg::Data(buf));
                });
            },
            TunnelMsg::SendData(id, buf) => {
                let _ = stream.write_u8(cs::DATA);
                let _ = stream.write_be_i32(id);
                let _ = stream.write_be_uint(buf.len());
                let _ = stream.write(buf.as_slice());
            }
        }
    }
}
