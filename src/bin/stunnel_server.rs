#[macro_use]
extern crate log;

use std::env;

use async_std::net::TcpListener;
use async_std::prelude::*;
use async_std::task;

use stunnel::logger;
use stunnel::tunnel::server::*;
use stunnel::ucp::{CsvMetricsService, UcpListener};

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

fn main() {
    let args: Vec<_> = env::args().collect();
    let program = args[0].clone();

    let mut opts = getopts::Options::new();
    opts.reqopt("l", "listen", "", "<IP:PORT>");
    opts.reqopt("k", "key", "", "<STRING>");
    opts.optopt("", "log", "", "<PATH>");
    opts.optopt("", "ucp-metrics-path", "", "<PATH>");

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(_) => {
            println!("{}", opts.usage(&program));
            return;
        }
    };

    let listen_addr = matches.opt_str("l").unwrap();
    let key = matches.opt_str("k").unwrap().into_bytes();
    let log_path = matches.opt_str("log").unwrap_or(String::new());
    let ucp_metrics_path = matches.opt_str("ucp-metrics-path").unwrap_or(String::new());

    logger::init(log::Level::Info, log_path, 1, 2000000).unwrap();
    info!("starting up");

    task::block_on(async move {
        let metrics = Box::new(CsvMetricsService::new(ucp_metrics_path));
        let ucp_listener = UcpListener::bind(&listen_addr, metrics).await;
        let tcp_listener = TcpListener::bind(&listen_addr).await.unwrap();

        let u = run_ucp_server(ucp_listener, key.clone());
        let t = run_tcp_server(tcp_listener, key.clone());
        u.join(t).await;
    });
}
