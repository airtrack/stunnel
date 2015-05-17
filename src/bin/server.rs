extern crate stunnel;

use std::env;
use std::net::TcpListener;
use stunnel::server::Tunnel;
use stunnel::cryptor::Cryptor;

fn main() {
    let args: Vec<_> = env::args().collect();
    if args.len() != 3 {
        println!("usage: {} listen-address key", args[0]);
        return
    }

    let listen_addr = args[1].clone();
    let key = args[2].clone().into_bytes();
    let (min, max) = Cryptor::key_size_range();

    if key.len() < min || key.len() > max {
        println!("key length must in range [{}, {}]", min, max);
        return
    }

    let listener = TcpListener::bind(&listen_addr[..]).unwrap();

    for stream in listener.incoming() {
        let key2 = key.clone();
        match stream {
            Ok(stream) => {
                Tunnel::new(key2, stream);
            },
            Err(_) => {}
        }
    }
}
