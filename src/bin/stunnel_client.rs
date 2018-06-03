#[macro_use]
extern crate log;
extern crate getopts;
extern crate stunnel;

use std::env;
use std::thread;
use std::io::Write;
use std::vec::Vec;
use std::net::TcpListener;
use std::net::TcpStream;
use std::net::ToSocketAddrs;
use std::str::from_utf8;

use stunnel::logger;
use stunnel::cryptor::Cryptor;
use stunnel::tcp::*;
use stunnel::client::*;
use stunnel::socks5::*;

fn tunnel_port_write(s: TcpStream, read_port: TunnelReadPort,
                     write_port: TunnelWritePort) {
    let mut stream = Tcp::new(s.try_clone().unwrap());

    match get_connect_dest(&mut stream) {
        Ok(ConnectDest::Addr(addr)) => {
            let mut buf = Vec::new();
            let _ = write!(&mut buf, "{}", addr);
            write_port.connect(buf);
        },

        Ok(ConnectDest::DomainName(domain_name, port)) => {
            write_port.connect_domain_name(domain_name, port);
        },

        _ => {
            return write_port.close();
        }
    }

    thread::spawn(move || {
        let _ = tunnel_port_read(s, read_port);
    });

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
    let addr = match read_port.read() {
        TunnelPortMsg::ConnectOk(buf) => {
            from_utf8(&buf[..]).unwrap().to_socket_addrs().unwrap().nth(0)
        },

        _ => None
    };

    let mut stream = Tcp::new(s);
    let ok = match addr {
        Some(addr) => reply_connect_success(&mut stream, addr).is_ok(),
        None => reply_failure(&mut stream).is_ok() && false
    };

    if !ok {
        stream.shutdown();
    }

    while ok {
        let buf = match read_port.read() {
            TunnelPortMsg::Data(buf) => buf,
            TunnelPortMsg::ShutdownWrite => {
                stream.shutdown_write();
                break
            },
            _ => {
                stream.shutdown();
                break
            }
        };

        match stream.write(&buf[..]) {
            Ok(_) => {},
            Err(_) => {
                stream.shutdown();
                break
            }
        }
    }
}

fn run_tunnels(listen_addr: String, server_addr: String,
               count: u32, key: Vec<u8>, enable_ucp: bool) {
    let mut tunnels = Vec::new();
    if enable_ucp {
        let tunnel = UcpTunnel::new(0, server_addr.clone(), key.clone());
        tunnels.push(tunnel);
    } else {
        for i in 0..count {
            let tunnel = TcpTunnel::new(i, server_addr.clone(), key.clone());
            tunnels.push(tunnel);
        }
    }

    let mut index = 0;
    let listener = TcpListener::bind(listen_addr.as_str()).unwrap();

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                {
                    let tunnel: &mut Tunnel = tunnels.get_mut(index).unwrap();
                    let (write_port, read_port) = tunnel.open_port();
                    thread::spawn(move || {
                        tunnel_port_write(stream, read_port, write_port);
                    });
                }

                index = (index + 1) % tunnels.len();
            },

            Err(_) => {}
        }
    }
}

fn main() {
    let args: Vec<_> = env::args().collect();
    let program = args[0].clone();

    let mut opts = getopts::Options::new();
    opts.reqopt("s", "server", "server address", "server-address");
    opts.reqopt("k", "key", "secret key", "key");
    opts.reqopt("c", "tunnel-count", "tunnel count", "tunnel-count");
    opts.optopt("l", "listen", "listen address", "listen-address");
    opts.optopt("", "log", "log path", "log-path");
    opts.optflag("", "enable-ucp", "enable ucp");

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => { m }
        Err(_) => {
            println!("{}", opts.short_usage(&program));
            return
        }
    };

    let server_addr = matches.opt_str("s").unwrap();
    let tunnel_count = matches.opt_str("c").unwrap();
    let key = matches.opt_str("k").unwrap().into_bytes();
    let log_path = matches.opt_str("log").unwrap_or(String::new());
    let enable_ucp = matches.opt_present("enable-ucp");
    let listen_addr = matches.opt_str("l")
        .unwrap_or("127.0.0.1:1080".to_string());
    let (min, max) = Cryptor::key_size_range();

    if key.len() < min || key.len() > max {
        println!("key length must in range [{}, {}]", min, max);
        return
    }

    let count: u32 = match tunnel_count.parse() {
        Err(_) | Ok(0) => {
            println!("tunnel-count must greater than 0");
            return
        },
        Ok(count) => count
    };

    logger::init(log::Level::Info, log_path, 1, 2000000).unwrap();
    info!("starting up");

    run_tunnels(listen_addr, server_addr, count, key, enable_ucp);
}
