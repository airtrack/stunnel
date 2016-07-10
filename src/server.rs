use std::sync::mpsc::channel;
use std::sync::mpsc::Sender;
use std::sync::mpsc::Receiver;
use std::thread;
use std::collections::HashMap;
use std::net::lookup_host;
use std::net::TcpStream;
use std::net::SocketAddr;
use std::io::Write;
use std::io::Error;
use std::io::ErrorKind;
use std::vec::Vec;
use std::str::from_utf8;
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
    OpenPort(u32),
    ClosePort(u32),
    Shutdown(u32),
    ConnectOk(u32, Vec<u8>),
    ConnectDN(u32, Vec<u8>, u16),
    RecvData(u8, u32, Vec<u8>),
    SendData(u32, Vec<u8>),
    CloseTunnel,
}

enum TunnelPortMsg {
    ConnectDN(Vec<u8>, u16),
    Data(u8, Vec<u8>),
    ClosePort,
}

pub struct Tunnel;

impl Copy for Tunnel {}
impl Clone for Tunnel {
    fn clone(&self) -> Self {
        *self
    }
}

impl Tunnel {
    pub fn new(key: Vec<u8>, stream: TcpStream) {
        thread::spawn(move || {
            tunnel_core_task(key, stream);
        });
    }
}

fn tunnel_port_recv(id: u32, receiver: TcpStream,
                    core_tx: Sender<TunnelMsg>) {
    let mut stream = Tcp::new(receiver);

    loop {
        let buf = match stream.read_at_most(10240) {
            Ok(buf) => buf,
            Err(_) => break
        };

        let _ = core_tx.send(TunnelMsg::SendData(id, buf));
    }

    stream.shutdown();
    let _ = core_tx.send(TunnelMsg::Shutdown(id));
}

fn tunnel_port_task(id: u32, rx: Receiver<TunnelPortMsg>,
                    core_tx: Sender<TunnelMsg>) {
    let os = match rx.recv().unwrap() {
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
            let _ = core_tx.send(TunnelMsg::Shutdown(id));
            return
        }
    };

    match s.local_addr() {
        Ok(addr) => {
            let mut buf = Vec::new();
            let _ = write!(&mut buf, "{}", addr);
            let _ = core_tx.send(TunnelMsg::ConnectOk(id, buf));
        },
        Err(_) => {
            let _ = core_tx.send(TunnelMsg::Shutdown(id));
            return
        }
    }

    let receiver = s.try_clone().unwrap();
    thread::spawn(move || {
        tunnel_port_recv(id, receiver, core_tx);
    });

    let mut stream = Tcp::new(s);
    loop {
        match rx.recv().unwrap() {
            TunnelPortMsg::Data(cs::DATA, buf) => {
                match stream.write(&buf[..]) {
                    Ok(_) => {},
                    Err(_) => break,
                }
            },
            _ => break
        }
    }

    stream.shutdown();
}

fn tunnel_tcp_recv(key: Vec<u8>, receiver: TcpStream,
                   core_tx: Sender<TunnelMsg>) {
    let mut stream = Tcp::new(receiver);
    let _ = tunnel_recv_loop(&key, &core_tx, &mut stream);

    stream.shutdown();
    let _ = core_tx.send(TunnelMsg::CloseTunnel);
}

fn tunnel_recv_loop(key: &Vec<u8>, core_tx: &Sender<TunnelMsg>,
                    stream: &mut Tcp) -> Result<(), Error> {
    let ctr = try!(stream.read_exact(Cryptor::ctr_size()));
    let mut decryptor = Cryptor::with_ctr(&key[..], ctr);

    let buf = try!(stream.read_exact(VERIFY_DATA.len()));
    let data = decryptor.decrypt(&buf[..]);
    if &data[..] != &VERIFY_DATA[..] {
        return Err(Error::new(ErrorKind::Other, "verify failed"));
    }

    loop {
        let op = try!(stream.read_u8());
        if op == cs::HEARTBEAT {
            let _ = core_tx.send(TunnelMsg::Heartbeat);
            continue
        }

        let id = try!(stream.read_u32());
        match op {
            cs::OPEN_PORT => {
                let _ = core_tx.send(TunnelMsg::OpenPort(id));
            },

            cs::CLOSE_PORT => {
                let _ = core_tx.send(TunnelMsg::ClosePort(id));
            },

            cs::CONNECT_DOMAIN_NAME => {
                let len = try!(stream.read_u32());
                let buf = try!(stream.read_exact((len - 2) as usize));
                let port = try!(stream.read_u16());
                let domain_name = decryptor.decrypt(&buf[..]);
                let _ = core_tx.send(TunnelMsg::ConnectDN(id, domain_name, port));
            },

            _ => {
                let len = try!(stream.read_u32());
                let buf = try!(stream.read_exact(len as usize));
                let data = decryptor.decrypt(&buf[..]);
                let _ = core_tx.send(TunnelMsg::RecvData(op, id, data));
            }
        }
    }
}

fn tunnel_core_task(key: Vec<u8>, sender: TcpStream) {
    let (core_tx, core_rx) = channel();
    let receiver = sender.try_clone().unwrap();
    let core_tx2 = core_tx.clone();
    let key2 = key.clone();

    thread::spawn(move || {
        tunnel_tcp_recv(key2, receiver, core_tx2);
    });

    let mut stream = Tcp::new(sender);
    let mut port_map = HashMap::<u32, Sender<TunnelPortMsg>>::new();

    let _ = tunnel_loop(&key, &core_tx, &core_rx, &mut stream, &mut port_map);

    stream.shutdown();
    for (_, tx) in port_map.iter() {
        let _ = tx.send(TunnelPortMsg::ClosePort);
    }
}

fn tunnel_loop(key: &Vec<u8>, core_tx: &Sender<TunnelMsg>,
               core_rx: &Receiver<TunnelMsg>, stream: &mut Tcp,
               port_map: &mut HashMap<u32, Sender<TunnelPortMsg>>
              ) -> Result<(), Error> {
    let mut encryptor = Cryptor::new(&key[..]);
    try!(stream.write(encryptor.ctr_as_slice()));

    let timer = Timer::new(HEARTBEAT_INTERVAL_MS);
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
                TunnelMsg::Heartbeat => {
                    alive_time = time::get_time();
                    try!(stream.write_u8(sc::HEARTBEAT_RSP));
                },

                TunnelMsg::OpenPort(id) => {
                    alive_time = time::get_time();
                    let (tx, rx) = channel();
                    port_map.insert(id, tx);

                    let core_tx2 = core_tx.clone();
                    thread::spawn(move || {
                        tunnel_port_task(id, rx, core_tx2);
                    });
                },

                TunnelMsg::ClosePort(id) => {
                    alive_time = time::get_time();
                    port_map.get(&id).map(|tx| {
                        let _ = tx.send(TunnelPortMsg::ClosePort);
                    });

                    port_map.remove(&id);
                },

                TunnelMsg::Shutdown(id) => {
                    let res = port_map.get(&id).map(|tx| {
                        let _ = tx.send(TunnelPortMsg::ClosePort);

                        try!(stream.write_u8(sc::SHUTDOWN));
                        try!(stream.write_u32(id));
                        Ok(())
                    });

                    match res {
                        Some(Err(e)) => return Err(e),
                        _ => {}
                    }

                    port_map.remove(&id);
                },

                TunnelMsg::ConnectOk(id, buf) => {
                    let data = encryptor.encrypt(&buf[..]);

                    try!(stream.write_u8(sc::CONNECT_OK));
                    try!(stream.write_u32(id));
                    try!(stream.write_u32(data.len() as u32));
                    try!(stream.write(&data[..]));
                },

                TunnelMsg::ConnectDN(id, domain_name, port) => {
                    alive_time = time::get_time();
                    port_map.get(&id).map(move |tx| {
                        let _ = tx.send(TunnelPortMsg::ConnectDN(domain_name, port));
                    });
                },

                TunnelMsg::RecvData(op, id, buf) => {
                    alive_time = time::get_time();
                    port_map.get(&id).map(move |tx| {
                        let _ = tx.send(TunnelPortMsg::Data(op, buf));
                    });
                },

                TunnelMsg::SendData(id, buf) => {
                    let data = encryptor.encrypt(&buf[..]);

                    try!(stream.write_u8(sc::DATA));
                    try!(stream.write_u32(id));
                    try!(stream.write_u32(data.len() as u32));
                    try!(stream.write(&data[..]));
                },

                TunnelMsg::CloseTunnel => break
            }
        }
    }

    Ok(())
}
