#[macro_use]
extern crate log;
extern crate stunnel;

use std::env;
use std::thread;
use std::io::Write;
use std::io::Error;
use std::vec::Vec;
use std::net::TcpListener;
use std::net::TcpStream;
use std::net::ToSocketAddrs;
use std::str::from_utf8;
use stunnel::logger;
use stunnel::tcp::Tcp;
use stunnel::cryptor::Cryptor;
use stunnel::client::{
    Tunnel, TunnelWritePort,
    TunnelReadPort, TunnelPortMsg
};
use stunnel::socks5::{
    ConnectDest, get_connect_dest,
    reply_connect_success, reply_failure
};

fn tunnel_port_write(s: TcpStream, mut write_port: TunnelWritePort,
                     read_port: TunnelReadPort) {
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
            write_port.close();
            return
        }
    }

    thread::spawn(move || {
        let _ = tunnel_port_read(s, read_port);
    });

    loop {
        match stream.read_at_most(10240) {
            Ok(buf) => {
                write_port.write(buf);
            },
            Err(_) => {
                write_port.close();
                break
            }
        }
    }

    stream.shutdown();
}

fn tunnel_port_read(s: TcpStream,
                    read_port: TunnelReadPort) -> Result<(), Error> {
    let addr = match read_port.read() {
        TunnelPortMsg::ConnectOk(buf) => {
            from_utf8(&buf[..]).unwrap().to_socket_addrs().unwrap().nth(0)
        },

        _ => None
    };

    let mut stream = Tcp::new(s);
    match addr {
        Some(addr) => {
            try!(reply_connect_success(&mut stream, addr));
        },
        None => {
            try!(reply_failure(&mut stream));
            return Ok(())
        }
    }

    loop {
        let buf = match read_port.read() {
            TunnelPortMsg::Data(buf) => buf,
            _ => break
        };

        match stream.write(&buf[..]) {
            Ok(_) => {},
            Err(_) => break,
        }
    }

    stream.shutdown();
    Ok(())
}

fn main() {
    let args: Vec<_> = env::args().collect();
    if args.len() < 4 {
        println!("usage: {} server-address key tunnel-count [log path]",
                 args[0]);
        return
    }

    let server_addr = args[1].clone();
    let key = args[2].clone().into_bytes();
    let (min, max) = Cryptor::key_size_range();

    if key.len() < min || key.len() > max {
        println!("key length must in range [{}, {}]", min, max);
        return
    }

    let count: u32 = match args[3].parse() {
        Err(_) | Ok(0) => {
            println!("tunnel-count must greater than 0");
            return
        },
        Ok(count) => count
    };

    let log_path = if args.len() > 4 {
        args[4].clone()
    } else {
        String::new()
    };

    logger::init(log::LogLevel::Info, log_path).unwrap();

    let mut tunnels = Vec::new();
    for i in 0..count {
        let tunnel = Tunnel::new(i, server_addr.clone(), key.clone());
        tunnels.push(tunnel);
    }

    let mut index = 0;
    let listener = TcpListener::bind("127.0.0.1:1080").unwrap();

    info!("starting up");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                {
                    let tunnel: &mut Tunnel = tunnels.get_mut(index).unwrap();
                    let (write_port, read_port) = tunnel.open_port();
                    thread::spawn(move || {
                        tunnel_port_write(stream, write_port, read_port);
                    });
                }

                index = (index + 1) % tunnels.len();
            },

            Err(_) => {}
        }
    }
}
