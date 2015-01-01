extern crate stunnel;

use std::io::TcpListener;
use std::io::{Acceptor, Listener};
use stunnel::server::Tunnel;

fn main() {
    let listener = TcpListener::bind("127.0.0.1:12345");
    let mut acceptor = listener.listen();

    for stream in acceptor.incoming() {
        match stream {
            Ok(stream) => {
                Tunnel::new(vec![1, 2, 3, 4], stream);
            },
            Err(_) => {}
        }
    }
}
