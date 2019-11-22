#[macro_use]
extern crate log;
extern crate async_std;
extern crate getopts;
extern crate stunnel;

use std::env;

use async_std::net::TcpListener;
use async_std::prelude::*;
use async_std::task;

use stunnel::cryptor::Cryptor;
use stunnel::logger;
use stunnel::server::*;
use stunnel::ucp::UcpListener;

fn main() {
    let args: Vec<_> = env::args().collect();
    let program = args[0].clone();

    let mut opts = getopts::Options::new();
    opts.reqopt("l", "listen", "listen address", "listen-address");
    opts.reqopt("k", "key", "secret key", "key");
    opts.optopt("", "log", "log path", "log-path");
    opts.optflag("", "enable-ucp", "enable ucp");

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(_) => {
            println!("{}", opts.short_usage(&program));
            return;
        }
    };

    let listen_addr = matches.opt_str("l").unwrap();
    let key = matches.opt_str("k").unwrap().into_bytes();
    let log_path = matches.opt_str("log").unwrap_or(String::new());
    let enable_ucp = matches.opt_present("enable-ucp");
    let (min, max) = Cryptor::key_size_range();

    if key.len() < min || key.len() > max {
        println!("key length must in range [{}, {}]", min, max);
        return;
    }

    logger::init(log::Level::Info, log_path, 1, 2000000).unwrap();
    info!("starting up");

    if enable_ucp {
        let k = key.clone();
        let addr = listen_addr.clone();
        task::spawn(async move {
            let mut listener = UcpListener::bind(&addr).await;

            loop {
                let stream = listener.incoming().await;
                UcpTunnel::new(k.clone(), stream);
            }
        });
    }

    task::block_on(async move {
        let listener = TcpListener::bind(&listen_addr).await.unwrap();
        let mut incoming = listener.incoming();

        while let Some(stream) = incoming.next().await {
            match stream {
                Ok(stream) => {
                    TcpTunnel::new(key.clone(), stream);
                }

                Err(_) => {}
            }
        }
    });
}
