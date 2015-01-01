extern crate stunnel;

use std::os;
use std::io::TcpListener;
use std::io::{Acceptor, Listener};
use stunnel::server::Tunnel;
use stunnel::crypto_wrapper::Cryptor;

fn main() {
    let args = os::args();
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

    let listener = TcpListener::bind(listen_addr.as_slice());
    let mut acceptor = listener.listen();

    for stream in acceptor.incoming() {
        let key2 = key.clone();
        match stream {
            Ok(stream) => {
                Tunnel::new(key2, stream);
            },
            Err(_) => {}
        }
    }
}
