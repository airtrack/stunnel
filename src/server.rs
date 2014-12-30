use std::thread::Thread;
use std::collections::HashMap;
use std::io::net::addrinfo::get_host_addresses;
use std::io::TcpStream;
use std::vec::Vec;
use std::path::BytesContainer;
use super::protocol::{cs, sc};

enum TunnelMsg {
    OpenPort(u32),
    ClosePort(u32),
    ConnectOk(u32, Vec<u8>),
    ConnectDN(u32, Vec<u8>, u16),
    RecvData(u8, u32, Vec<u8>),
    SendData(u32, Vec<u8>),
    Shutdown(u32),
    CloseTunnel,
}

enum TunnelPortMsg {
    ConnectDN(Vec<u8>, u16),
    Data(u8, Vec<u8>),
    ClosePort,
}

pub struct Tunnel;

impl Copy for Tunnel {}
impl Tunnel {
    pub fn new(stream: TcpStream) {
        Thread::spawn(move || {
            tunnel_core_task(stream);
        }).detach();
    }
}

fn tunnel_port_recv(id: u32, mut stream: TcpStream, core_tx: Sender<TunnelMsg>) {
    loop {
        let mut buf = Vec::with_capacity(1024);
        unsafe { buf.set_len(1024); }

        match stream.read(buf.as_mut_slice()) {
            Ok(len) => {
                unsafe { buf.set_len(len); }
                core_tx.send(TunnelMsg::SendData(id, buf));
            },
            Err(_) => {
                core_tx.send(TunnelMsg::Shutdown(id));
                break
            }
        }
    }
}

fn tunnel_port_task(id: u32, rx: Receiver<TunnelPortMsg>, core_tx: Sender<TunnelMsg>) {
    let stream_o = match rx.recv() {
        TunnelPortMsg::Data(cs::CONNECT, buf) => {
            buf.container_as_str().and_then(|addr| TcpStream::connect(addr).ok())
        },
        TunnelPortMsg::ConnectDN(domain_name, port) => {
            match domain_name.container_as_str().and_then(
                |host| get_host_addresses(host).ok()) {
                Some(ip_vec) => {
                    if ip_vec.len() == 0 { None }
                    else { TcpStream::connect((ip_vec[0], port)).ok() }
                },
                None => None
            }
        },
        _ => None
    };

    let mut stream = match stream_o {
        Some(stream) => stream,
        None => { return core_tx.send(TunnelMsg::Shutdown(id)); }
    };

    match stream.socket_name() {
        Ok(addr) => {
            let mut buf = Vec::new();
            let _ = write!(&mut buf, "{}", addr);
            core_tx.send(TunnelMsg::ConnectOk(id, buf));
        },
        Err(_) => { return core_tx.send(TunnelMsg::Shutdown(id)); }
    }

    let receiver = stream.clone();
    Thread::spawn(move || {
        tunnel_port_recv(id, receiver, core_tx);
    }).detach();

    loop {
        match rx.recv() {
            TunnelPortMsg::Data(cs::DATA, buf) => {
                let _ = stream.write(buf.as_slice());
            },
            _ => break
        }
    }

    let _ = stream.close_read();
}

fn tunnel_tcp_recv(mut stream: TcpStream, core_tx: Sender<TunnelMsg>) {
    loop {
        let op = match stream.read_byte() {
            Ok(op) => op,
            Err(_) => break
        };

        let id = match stream.read_be_u32() {
            Ok(id) => id,
            Err(_) => break
        };

        match op {
            cs::OPEN_PORT => {
                core_tx.send(TunnelMsg::OpenPort(id));
            },
            cs::CLOSE_PORT => {
                core_tx.send(TunnelMsg::ClosePort(id));
            },
            cs::CONNECT_DOMAIN_NAME => {
                let len = match stream.read_be_u32() {
                    Ok(len) => len,
                    Err(_) => break
                };

                let domain_name = match stream.read_exact(len as uint - 2) {
                    Ok(domain_name) => domain_name,
                    Err(_) => break
                };

                let port = match stream.read_be_u16() {
                    Ok(port) => port,
                    Err(_) => break
                };

                core_tx.send(TunnelMsg::ConnectDN(id, domain_name, port));
            },
            _ => {
                let len = match stream.read_be_u32() {
                    Ok(len) => len,
                    Err(_) => break
                };

                let buf = match stream.read_exact(len as uint) {
                    Ok(buf) => buf,
                    Err(_) => break
                };

                core_tx.send(TunnelMsg::RecvData(op, id, buf));
            }
        }
    }

    core_tx.send(TunnelMsg::CloseTunnel);
}

fn tunnel_core_task(mut stream: TcpStream) {
    let (core_tx, core_rx) = channel();
    let receiver = stream.clone();
    let core_tx2 = core_tx.clone();
    Thread::spawn(move || {
        tunnel_tcp_recv(receiver, core_tx2);
    }).detach();

    let mut port_map = HashMap::new();
    loop {
        match core_rx.recv() {
            TunnelMsg::OpenPort(id) => {
                let (tx, rx) = channel();
                port_map.insert(id, tx);

                let core_tx2 = core_tx.clone();
                Thread::spawn(move || {
                    tunnel_port_task(id, rx, core_tx2);
                }).detach();
            },
            TunnelMsg::ClosePort(id) => {
                port_map.get(&id).map(|tx| {
                    let _ = tx.send_opt(TunnelPortMsg::ClosePort);
                });

                port_map.remove(&id);
            },
            TunnelMsg::ConnectOk(id, buf) => {
                let _ = stream.write_u8(sc::CONNECT_OK);
                let _ = stream.write_be_u32(id);
                let _ = stream.write_be_u32(buf.len() as u32);
                let _ = stream.write(buf.as_slice());
            },
            TunnelMsg::ConnectDN(id, domain_name, port) => {
                port_map.get(&id).map(move |tx| {
                    let _ = tx.send_opt(TunnelPortMsg::ConnectDN(domain_name, port));
                });
            },
            TunnelMsg::RecvData(op, id, buf) => {
                port_map.get(&id).map(move |tx| {
                    let _ = tx.send_opt(TunnelPortMsg::Data(op, buf));
                });
            },
            TunnelMsg::SendData(id, buf) => {
                let _ = stream.write_u8(sc::DATA);
                let _ = stream.write_be_u32(id);
                let _ = stream.write_be_u32(buf.len() as u32);
                let _ = stream.write(buf.as_slice());
            },
            TunnelMsg::Shutdown(id) => {
                port_map.get(&id).map(|tx| {
                    let _ = tx.send_opt(TunnelPortMsg::ClosePort);

                    let _ = stream.write_u8(sc::SHUTDOWN);
                    let _ = stream.write_be_u32(id);
                });

                port_map.remove(&id);
            },
            TunnelMsg::CloseTunnel => break
        }
    }

    for (_, tx) in port_map.iter() {
        tx.send(TunnelPortMsg::ClosePort);
    }
}
