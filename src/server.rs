use std::sync::mpsc::sync_channel;
use std::sync::mpsc::channel;
use std::sync::mpsc::SyncSender;
use std::sync::mpsc::Sender;
use std::sync::mpsc::Receiver;
use std::thread;
use std::collections::HashMap;
use std::net::lookup_host;
use std::net::TcpStream;
use std::net::SocketAddr;
use std::io::Write;
use std::vec::Vec;
use std::str::from_utf8;
use time;
use super::timer::Timer;
use super::cryptor::Cryptor;
use super::tcp::{Tcp, TcpError};
use super::protocol::{
    VERIFY_DATA, cs, sc,
    HEARTBEAT_INTERVAL_MS,
    ALIVE_TIMEOUT_TIME_MS
};

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
    CloseTunnel,
}

enum TunnelPortMsg {
    ConnectDN(Vec<u8>, u16),
    Data(u8, Vec<u8>),
    ShutdownWrite,
    ClosePort,
}

pub struct Tunnel;

struct TunnelWritePort {
    id: u32,
    tx: SyncSender<TunnelMsg>,
}

struct TunnelReadPort {
    id: u32,
    tx: SyncSender<TunnelMsg>,
    rx: Receiver<TunnelPortMsg>,
}

struct PortMapValue {
    count: u32,
    tx: Sender<TunnelPortMsg>,
}

type PortMap = HashMap<u32, PortMapValue>;

impl Tunnel {
    pub fn new(key: Vec<u8>, stream: TcpStream) {
        thread::spawn(move || {
            tunnel_core_task(key, stream);
        });
    }
}

impl Copy for Tunnel {
}

impl Clone for Tunnel {
    fn clone(&self) -> Self {
        *self
    }
}

impl TunnelWritePort {
    fn connect_ok(&self, buf: Vec<u8>) {
        let _ = self.tx.send(TunnelMsg::SCConnectOk(self.id, buf));
    }

    fn write(&self, buf: Vec<u8>) {
        let _ = self.tx.send(TunnelMsg::SCData(self.id, buf));
    }

    fn shutdown_write(&self) {
        let _ = self.tx.send(TunnelMsg::SCShutdownWrite(self.id));
    }

    fn close(&self) {
        let _ = self.tx.send(TunnelMsg::SCClosePort(self.id));
    }
}

impl Drop for TunnelWritePort {
    fn drop(&mut self) {
        let _ = self.tx.send(TunnelMsg::TunnelPortDrop(self.id));
    }
}

impl TunnelReadPort {
    fn read(&self) -> TunnelPortMsg {
        self.rx.recv().unwrap()
    }
}

impl Drop for TunnelReadPort {
    fn drop(&mut self) {
        let _ = self.tx.send(TunnelMsg::TunnelPortDrop(self.id));
    }
}

fn tunnel_port_write(s: TcpStream, write_port: TunnelWritePort) {
    let mut stream = Tcp::new(s);

    loop {
        match stream.read_at_most(1024) {
            Ok(buf) => {
                write_port.write(buf);
            },
            Err(TcpError::Eof) => {
                stream.shutdown_read();
                write_port.shutdown_write();
                break
            },
            Err(_) => {
                stream.shutdown();
                write_port.close();
                break
            }
        }
    }
}

fn tunnel_port_read(s: TcpStream, read_port: TunnelReadPort) {
    let mut stream = Tcp::new(s);

    loop {
        match read_port.read() {
            TunnelPortMsg::Data(cs::DATA, buf) => {
                match stream.write(&buf[..]) {
                    Ok(_) => {},
                    Err(_) => {
                        stream.shutdown();
                        break
                    }
                }
            },
            TunnelPortMsg::ShutdownWrite => {
                stream.shutdown_write();
                break
            },
            _ => {
                stream.shutdown();
                break
            }
        }
    }
}

fn tunnel_port_task(read_port: TunnelReadPort, write_port: TunnelWritePort) {
    let os = match read_port.read() {
        TunnelPortMsg::Data(cs::CONNECT, buf) => {
            TcpStream::connect(from_utf8(&buf[..]).unwrap()).ok()
        },
        TunnelPortMsg::ConnectDN(domain_name, port) => {
            match lookup_host(from_utf8(&domain_name[..]).unwrap()) {
                Ok(hosts) => {
                    let mut stream = None;
                    for host in hosts {
                        let conn = match host {
                            SocketAddr::V4(addr_v4) =>
                                TcpStream::connect((addr_v4.ip().clone(), port)),
                                SocketAddr::V6(addr_v6) =>
                                    TcpStream::connect((addr_v6.ip().clone(), port))
                        };
                        match conn {
                            Ok(s) => { stream = Some(s); break; },
                            Err(_) => {}
                        }
                    }
                    stream
                },
                Err(_) => None
            }
        },
        _ => None
    };

    let s = match os {
        Some(s) => s,
        None => {
            return write_port.close();
        }
    };

    match s.local_addr() {
        Ok(addr) => {
            let mut buf = Vec::new();
            let _ = write!(&mut buf, "{}", addr);
            write_port.connect_ok(buf);
        },
        Err(_) => {
            return write_port.close();
        }
    }

    let receiver = s.try_clone().unwrap();
    thread::spawn(move || {
        tunnel_port_write(receiver, write_port);
    });

    tunnel_port_read(s, read_port);
}

fn tunnel_tcp_recv(key: Vec<u8>, receiver: TcpStream,
                   core_tx: SyncSender<TunnelMsg>) {
    let mut stream = Tcp::new(receiver);
    let _ = tunnel_recv_loop(&key, &core_tx, &mut stream);

    stream.shutdown();
    let _ = core_tx.send(TunnelMsg::CloseTunnel);
}

fn tunnel_recv_loop(key: &Vec<u8>, core_tx: &SyncSender<TunnelMsg>,
                    stream: &mut Tcp) -> Result<(), TcpError> {
    let ctr = try!(stream.read_exact(Cryptor::ctr_size()));
    let mut decryptor = Cryptor::with_ctr(&key[..], ctr);

    let buf = try!(stream.read_exact(VERIFY_DATA.len()));
    let data = decryptor.decrypt(&buf[..]);
    if &data[..] != &VERIFY_DATA[..] {
        return Err(TcpError::ErrorData);
    }

    loop {
        let op = try!(stream.read_u8());
        if op == cs::HEARTBEAT {
            let _ = core_tx.send(TunnelMsg::CSHeartbeat);
            continue
        }

        let id = try!(stream.read_u32());
        match op {
            cs::OPEN_PORT => {
                let _ = core_tx.send(TunnelMsg::CSOpenPort(id));
            },

            cs::CLOSE_PORT => {
                let _ = core_tx.send(TunnelMsg::CSClosePort(id));
            },

            cs::SHUTDOWN_WRITE => {
                let _ = core_tx.send(TunnelMsg::CSShutdownWrite(id));
            },

            cs::CONNECT_DOMAIN_NAME => {
                let len = try!(stream.read_u32());
                let buf = try!(stream.read_exact((len - 2) as usize));
                let port = try!(stream.read_u16());
                let domain_name = decryptor.decrypt(&buf[..]);
                let _ = core_tx.send(TunnelMsg::CSConnectDN(id, domain_name, port));
            },

            _ => {
                let len = try!(stream.read_u32());
                let buf = try!(stream.read_exact(len as usize));
                let data = decryptor.decrypt(&buf[..]);
                let _ = core_tx.send(TunnelMsg::CSData(op, id, data));
            }
        }
    }
}

fn tunnel_core_task(key: Vec<u8>, sender: TcpStream) {
    let (core_tx, core_rx) = sync_channel(10000);
    let receiver = sender.try_clone().unwrap();
    let core_tx2 = core_tx.clone();
    let key2 = key.clone();

    thread::spawn(move || {
        tunnel_tcp_recv(key2, receiver, core_tx2);
    });

    let mut stream = Tcp::new(sender);
    let mut port_map = PortMap::new();

    let _ = tunnel_loop(&key, &core_tx, &core_rx, &mut stream, &mut port_map);

    stream.shutdown();
    for (_, value) in port_map.iter() {
        let _ = value.tx.send(TunnelPortMsg::ClosePort);
    }
}

fn tunnel_loop(key: &Vec<u8>, core_tx: &SyncSender<TunnelMsg>,
               core_rx: &Receiver<TunnelMsg>, stream: &mut Tcp,
               port_map: &mut PortMap) -> Result<(), TcpError> {
    let mut encryptor = Cryptor::new(&key[..]);
    try!(stream.write(encryptor.ctr_as_slice()));

    let timer = Timer::new(HEARTBEAT_INTERVAL_MS as u32);
    let mut alive_time = time::get_time();

    loop {
        select! {
            _ = timer.recv() => {
                let duration = time::get_time() - alive_time;
                if duration.num_milliseconds() > ALIVE_TIMEOUT_TIME_MS {
                    break
                }
            },

            msg = core_rx.recv() => match msg.unwrap() {
                TunnelMsg::CSHeartbeat => {
                    alive_time = time::get_time();
                    try!(stream.write_u8(sc::HEARTBEAT_RSP));
                },

                TunnelMsg::CSOpenPort(id) => {
                    alive_time = time::get_time();
                    let (tx, rx) = channel();
                    port_map.insert(id, PortMapValue { count: 2, tx: tx });

                    let read_port = TunnelReadPort {
                        id: id, tx: core_tx.clone(), rx: rx
                    };
                    let write_port = TunnelWritePort {
                        id: id, tx: core_tx.clone()
                    };

                    thread::spawn(move || {
                        tunnel_port_task(read_port, write_port);
                    });
                },

                TunnelMsg::CSClosePort(id) => {
                    alive_time = time::get_time();
                    port_map.get(&id).map(|value| {
                        let _ = value.tx.send(TunnelPortMsg::ClosePort);
                    });

                    port_map.remove(&id);
                },

                TunnelMsg::CSShutdownWrite(id) => {
                    alive_time = time::get_time();
                    port_map.get(&id).map(|value| {
                        let _ = value.tx.send(TunnelPortMsg::ShutdownWrite);
                    });
                }

                TunnelMsg::CSConnectDN(id, domain_name, port) => {
                    alive_time = time::get_time();
                    port_map.get(&id).map(move |value| {
                        let _ = value.tx.send(TunnelPortMsg::ConnectDN(domain_name, port));
                    });
                },

                TunnelMsg::CSData(op, id, buf) => {
                    alive_time = time::get_time();
                    port_map.get(&id).map(move |value| {
                        let _ = value.tx.send(TunnelPortMsg::Data(op, buf));
                    });
                },

                TunnelMsg::SCClosePort(id) => {
                    let res = port_map.get(&id).map(|value| {
                        let _ = value.tx.send(TunnelPortMsg::ClosePort);

                        try!(stream.write_u8(sc::CLOSE_PORT));
                        try!(stream.write_u32(id));
                        Ok(())
                    });

                    match res {
                        Some(Err(e)) => return Err(e),
                        _ => {}
                    }

                    port_map.remove(&id);
                },

                TunnelMsg::SCShutdownWrite(id) => {
                    try!(stream.write_u8(sc::SHUTDOWN_WRITE));
                    try!(stream.write_u32(id));
                },

                TunnelMsg::SCConnectOk(id, buf) => {
                    let data = encryptor.encrypt(&buf[..]);

                    try!(stream.write_u8(sc::CONNECT_OK));
                    try!(stream.write_u32(id));
                    try!(stream.write_u32(data.len() as u32));
                    try!(stream.write(&data[..]));
                },

                TunnelMsg::SCData(id, buf) => {
                    let data = encryptor.encrypt(&buf[..]);

                    try!(stream.write_u8(sc::DATA));
                    try!(stream.write_u32(id));
                    try!(stream.write_u32(data.len() as u32));
                    try!(stream.write(&data[..]));
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
                        port_map.remove(&id);
                    }
                },

                TunnelMsg::CloseTunnel => break
            }
        }
    }

    Ok(())
}
