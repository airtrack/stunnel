extern crate stunnel;

use std::os;
use std::thread::Thread;
use std::io::{TcpListener, TcpStream};
use std::io::{Acceptor, Listener};
use std::io::net::ip::ToSocketAddr;
use std::vec::Vec;
use std::path::BytesContainer;
use stunnel::client::{Tunnel, TunnelWritePort, TunnelReadPort, TunnelPortMsg};
use stunnel::socks5::{ConnectDest, get_connect_dest, reply_connect_success, reply_failure};
use stunnel::crypto_wrapper::Cryptor;

fn tunnel_port_write(mut stream: TcpStream, mut write_port: TunnelWritePort,
                     read_port: TunnelReadPort) {
    match get_connect_dest(stream.clone()) {
        ConnectDest::Addr(addr) => {
            let mut buf = Vec::new();
            let _ = write!(&mut buf, "{}", addr);
            write_port.connect(buf);
        },
        ConnectDest::DomainName(domain_name, port) => {
            write_port.connect_domain_name(domain_name, port);
        },
        _ => {
            write_port.close();
            return
        }
    }

    let sender = stream.clone();
    Thread::spawn(move || {
        tunnel_port_read(sender, read_port);
    }).detach();

    loop {
        let mut buf = Vec::with_capacity(1024);
        unsafe { buf.set_len(1024); }

        match stream.read(buf.as_mut_slice()) {
            Ok(len) => {
                unsafe { buf.set_len(len); }
                write_port.write(buf);
            },
            Err(_) => {
                write_port.close();
                break;
            }
        }
    }
}

fn tunnel_port_read(mut stream: TcpStream, read_port: TunnelReadPort) {
    let addr = match read_port.read() {
        TunnelPortMsg::ConnectOk(buf) => {
            buf.container_as_str().and_then(|addr| addr.to_socket_addr().ok())
        },
        _ => None
    };

    match addr {
        Some(addr) => {
            reply_connect_success(stream.clone(), addr);
        },
        None => {
            reply_failure(stream.clone());
            let _ = stream.close_read();
            return
        }
    }

    loop {
        let buf = match read_port.read() {
            TunnelPortMsg::Data(buf) => buf,
            _ => break
        };

        match stream.write(buf.as_slice()) {
            Ok(_) => {},
            Err(_) => break
        }
    }

    let _ = stream.close_read();
}

fn main() {
    let args = os::args();
    if args.len() != 3 {
        println!("usage: {} server-address key", args[0]);
        return
    }

    let server_addr = args[1].clone();
    let key = args[2].clone().into_bytes();
    let (min, max) = Cryptor::key_size_range();

    if key.len() < min || key.len() > max {
        println!("key length must in range [{}, {}]", min, max);
        return
    }

    let mut tunnel = Tunnel::new(server_addr, key);

    let listener = TcpListener::bind("127.0.0.1:1080");
    let mut acceptor = listener.listen();

    for stream in acceptor.incoming() {
        match stream {
            Ok(stream) => {
                let (write_port, read_port) = tunnel.open_port();

                Thread::spawn(move || {
                    tunnel_port_write(stream, write_port, read_port);
                }).detach();
            },
            Err(_) => {}
        }
    }
}
