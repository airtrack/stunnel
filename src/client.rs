use std::thread::Thread;
use std::collections::HashMap;
use std::io::{TcpStream, Timer};
use std::time::Duration;
use std::vec::Vec;
use time;
use super::crypto_wrapper::Cryptor;
use super::protocol::{
    VERIFY_DATA, HEARTBEAT_INTERVAL, ALIVE_TIMEOUT_TIME, cs, sc
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
    CloseTunnel,
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

        Thread::spawn(move || {
            tunnel_core_task(server_addr, key, rx, tx2);
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

fn tunnel_tcp_recv(key: Vec<u8>, mut stream: TcpStream,
                   core_tx: Sender<TunnelMsg>) {
    let mut decryptor = match stream.read_exact(Cryptor::ctr_size()) {
        Ok(ctr) => Cryptor::with_ctr(key.as_slice(), ctr),
        Err(_) => return core_tx.send(TunnelMsg::CloseTunnel)
    };

    loop {
        let op = ok_or_break!(stream.read_u8());
        if op == sc::HEARTBEAT_RSP {
            core_tx.send(TunnelMsg::Heartbeat);
            continue
        }

        let id = ok_or_break!(stream.read_be_u32());

        match op {
            sc::CONNECT_OK => {
                let len = ok_or_break!(stream.read_be_u32());

                match stream.read_exact(len as uint) {
                    Ok(buf) => {
                        let data = decryptor.decrypt(buf.as_slice());
                        core_tx.send(TunnelMsg::ConnectOk(id, data));
                    },
                    Err(_) => break
                }
            },
            sc::SHUTDOWN => {
                core_tx.send(TunnelMsg::Shutdown(id));
            },
            sc::DATA => {
                let len = ok_or_break!(stream.read_be_u32());

                match stream.read_exact(len as uint) {
                    Ok(buf) => {
                        let data = decryptor.decrypt(buf.as_slice());
                        core_tx.send(TunnelMsg::RecvData(id, data));
                    },
                    Err(_) => break
                }
            },
            _ => break
        }
    }

    core_tx.send(TunnelMsg::CloseTunnel);
}

fn tunnel_core_task(server_addr: String, key: Vec<u8>,
                    core_rx: Receiver<TunnelMsg>, core_tx: Sender<TunnelMsg>) {
    let mut stream = TcpStream::connect(server_addr.as_slice()).unwrap();
    let receiver = stream.clone();
    let core_tx2 = core_tx.clone();
    let key2 = key.clone();

    Thread::spawn(move || {
        tunnel_tcp_recv(key2, receiver, core_tx2);
    }).detach();

    let mut encryptor = Cryptor::new(key.as_slice());
    on_error!(stream.close_read(),
        stream.write(encryptor.ctr_as_slice()),
        stream.write(encryptor.encrypt(&VERIFY_DATA).as_slice()));

    let mut timer = Timer::new().unwrap();
    let heartbeat = timer.periodic(Duration::seconds(HEARTBEAT_INTERVAL));
    let mut alive_time = time::get_time();

    let mut port_map = HashMap::new();
    loop {
        select!(
            _ = heartbeat.recv() => {
                if (time::get_time() - alive_time).num_seconds() > ALIVE_TIMEOUT_TIME {
                    let _ = stream.close_read();
                }
                on_error!(stream.close_read(),
                    stream.write_u8(cs::HEARTBEAT));
            },
            msg = core_rx.recv() => match msg {
                TunnelMsg::Heartbeat => {
                    alive_time = time::get_time();
                },
                TunnelMsg::OpenPort(id, tx) => {
                    port_map.insert(id, tx);

                    on_error!(stream.close_read(),
                        stream.write_u8(cs::OPEN_PORT),
                        stream.write_be_u32(id));
                },
                TunnelMsg::ClosePort(id) => {
                    port_map.get(&id).map(|tx| {
                        let _ = tx.send_opt(TunnelPortMsg::ClosePort);

                        on_error!(stream.close_read(),
                            stream.write_u8(cs::CLOSE_PORT),
                            stream.write_be_u32(id));
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
                    let data = encryptor.encrypt(buf.as_slice());

                    on_error!(stream.close_read(),
                        stream.write_u8(cs::CONNECT),
                        stream.write_be_u32(id),
                        stream.write_be_u32(data.len() as u32),
                        stream.write(data.as_slice()));
                },
                TunnelMsg::ConnectDN(id, buf, port) => {
                    let data = encryptor.encrypt(buf.as_slice());

                    on_error!(stream.close_read(),
                        stream.write_u8(cs::CONNECT_DOMAIN_NAME),
                        stream.write_be_u32(id),
                        stream.write_be_u32(data.len() as u32 + 2),
                        stream.write(data.as_slice()),
                        stream.write_be_u16(port));
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
                    let data = encryptor.encrypt(buf.as_slice());

                    on_error!(stream.close_read(),
                        stream.write_u8(cs::DATA),
                        stream.write_be_u32(id),
                        stream.write_be_u32(data.len() as u32),
                        stream.write(data.as_slice()));
                },
                TunnelMsg::CloseTunnel => break
            }
        )
    }

    for (_, tx) in port_map.iter() {
        let _ = tx.send_opt(TunnelPortMsg::ClosePort);
    }

    Thread::spawn(move || {
        tunnel_core_task(server_addr, key, core_rx, core_tx);
    }).detach();
}
