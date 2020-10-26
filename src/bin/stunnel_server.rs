#[macro_use]
extern crate log;
extern crate async_std;
extern crate getopts;
extern crate stunnel;
extern crate tide;

use std::env;

use async_std::net::TcpListener;
use async_std::prelude::*;
use async_std::task;

use stunnel::cryptor::Cryptor;
use stunnel::logger;
use stunnel::server::*;
use stunnel::ucp::UcpListener;

async fn run_ucp_server(mut listener: UcpListener, key: Vec<u8>) {
    loop {
        let stream = listener.incoming().await;
        UcpTunnel::new(key.clone(), stream);
    }
}

async fn run_tcp_server(listener: TcpListener, key: Vec<u8>) {
    let mut incoming = listener.incoming();

    while let Some(stream) = incoming.next().await {
        match stream {
            Ok(stream) => {
                TcpTunnel::new(key.clone(), stream);
            }

            Err(_) => {}
        }
    }
}

async fn run_http_server(mut app: tide::Server<()>, addr: String) {
    app.at("/").get(|_| async { Ok("Hello, world!") });
    let _ = app.listen(addr).await;
}

fn main() {
    let args: Vec<_> = env::args().collect();
    let program = args[0].clone();

    let mut opts = getopts::Options::new();
    opts.reqopt("l", "listen", "listen address", "listen-address");
    opts.reqopt("k", "key", "secret key", "key");
    opts.optopt("", "log", "log path", "log-path");
    opts.optopt("", "http", "http address", "http-address");

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
    let http_addr = matches
        .opt_str("http")
        .unwrap_or(String::from("127.0.0.1:8080"));
    let (min, max) = Cryptor::key_size_range();

    if key.len() < min || key.len() > max {
        println!("key length must in range [{}, {}]", min, max);
        return;
    }

    logger::init(log::Level::Info, log_path, 1, 2000000).unwrap();
    info!("starting up");

    task::block_on(async move {
        let ucp_listener = UcpListener::bind(&listen_addr).await;
        let tcp_listener = TcpListener::bind(&listen_addr).await.unwrap();
        let http_app = tide::new();

        let u = run_ucp_server(ucp_listener, key.clone());
        let t = run_tcp_server(tcp_listener, key.clone());
        let h = run_http_server(http_app, http_addr);
        u.join(t).join(h).await;
    });
}
