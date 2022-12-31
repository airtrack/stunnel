#[macro_use]
extern crate log;

use std::env;
use std::vec::Vec;

use async_std::net::{SocketAddr, TcpListener};
use async_std::prelude::*;
use async_std::task;

use stunnel::client::*;
use stunnel::cryptor::Cryptor;
use stunnel::logger;
use stunnel::proxy::{http, socks5, Proxy};
use stunnel::ucp::CsvMetricsService;

async fn run_proxy_tunnels(
    mut tunnels: Vec<Tunnel>,
    socks5_addr: SocketAddr,
    http_addr: SocketAddr,
) {
    let mut index = 0;
    let socks5_listener = TcpListener::bind(socks5_addr).await.unwrap();
    let http_listener = TcpListener::bind(http_addr).await.unwrap();
    let socks5_incoming = socks5_listener.incoming();
    let http_incoming = http_listener.incoming();
    let mut incoming = socks5_incoming.merge(http_incoming);

    while let Some(stream) = incoming.next().await {
        match stream {
            Ok(stream) => match stream.local_addr() {
                Ok(addr) => {
                    let tunnel: &mut Tunnel = tunnels.get_mut(index).unwrap();
                    let (write_port, read_port) = tunnel.open_port().await;

                    if addr.port() == http_addr.port() {
                        let mut proxy = http::Http;
                        task::spawn(async move {
                            proxy.run_proxy_tunnel(stream, read_port, write_port).await;
                        });
                    } else {
                        let mut proxy = socks5::Socks5::new();
                        task::spawn(async move {
                            proxy.run_proxy_tunnel(stream, read_port, write_port).await;
                        });
                    }

                    index = (index + 1) % tunnels.len();
                }

                Err(_) => {}
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
    opts.optopt(
        "c",
        "tcp-tunnel-count",
        "tcp tunnel count",
        "tcp-tunnel-count",
    );
    opts.optopt(
        "",
        "socks5-proxy",
        "socks5 proxy listen address",
        "socks5-proxy-address",
    );
    opts.optopt(
        "",
        "http-proxy",
        "http proxy listen address",
        "http-proxy-address",
    );
    opts.optopt("", "log", "log path", "log-path");
    opts.optopt("", "ucp-metrics-path", "metrics path", "metrics-path");
    opts.optflag("", "enable-ucp", "enable ucp");

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(_) => {
            println!("{}", opts.short_usage(&program));
            return;
        }
    };

    let server_addr = matches.opt_str("s").unwrap();
    let tunnel_count = matches.opt_str("c").unwrap_or(String::new());
    let key = matches.opt_str("k").unwrap().into_bytes();
    let log_path = matches.opt_str("log").unwrap_or(String::new());
    let ucp_metrics_path = matches.opt_str("ucp-metrics-path").unwrap_or(String::new());
    let enable_ucp = matches.opt_present("enable-ucp");
    let socks5_proxy_addr = matches
        .opt_str("socks5-proxy")
        .unwrap_or(String::from("127.0.0.1:1080"));
    let http_proxy_addr = matches
        .opt_str("http-proxy")
        .unwrap_or(String::from("127.0.0.1:8888"));
    let (min, max) = Cryptor::key_size_range();

    if key.len() < min || key.len() > max {
        println!("key length must in range [{}, {}]", min, max);
        return;
    }

    let count: u32 = match tunnel_count.parse() {
        Err(_) | Ok(0) => 1,
        Ok(count) => count,
    };

    logger::init(log::Level::Info, log_path, 1, 2000000).unwrap();
    info!("starting up");

    task::block_on(async move {
        let mut tunnels = Vec::new();

        if enable_ucp {
            let metrics = Box::new(CsvMetricsService::new(ucp_metrics_path));
            let tunnel = UcpTunnel::new(0, server_addr.clone(), key.clone(), metrics);
            tunnels.push(tunnel);
        } else {
            for i in 0..count {
                let tunnel = TcpTunnel::new(i, server_addr.clone(), key.clone());
                tunnels.push(tunnel);
            }
        }

        let socks5_proxy_addr = socks5_proxy_addr.parse().unwrap();
        let http_proxy_addr = http_proxy_addr.parse().unwrap();
        run_proxy_tunnels(tunnels, socks5_proxy_addr, http_proxy_addr).await;
    });
}
