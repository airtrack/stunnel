extern crate getopts;
extern crate stunnel;

use std::env;
use std::net::TcpListener;
use stunnel::server::TcpTunnel;
use stunnel::cryptor::Cryptor;

fn main() {
    let args: Vec<_> = env::args().collect();
    let program = args[0].clone();

    let mut opts = getopts::Options::new();
    opts.reqopt("l", "listen", "listen address", "listen-address");
    opts.reqopt("k", "key", "secret key", "key");

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => { m }
        Err(_) => {
            println!("{}", opts.short_usage(&program));
            return
        }
    };

    let listen_addr = matches.opt_str("l").unwrap();
    let key = matches.opt_str("k").unwrap().into_bytes();
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
                TcpTunnel::new(key2, stream);
            },
            Err(_) => {}
        }
    }
}
