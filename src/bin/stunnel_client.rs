use std::{env, fs};

use log::{error, info};
use quinn::Connection;
use stunnel::proxy::{http::HttpProxy, socks5::Socks5Proxy};
use stunnel::proxy::{Proxy, ProxyType, TcpProxyConn, UdpProxyBind};
use stunnel::quic::client;
use stunnel::tunnel::start_tcp_tunnel;
use tokio::{net::TcpListener, runtime::Runtime};

async fn proxy<T: TcpProxyConn + Send, U: UdpProxyBind + Send>(
    proxy: impl Proxy<T, U> + Sync + Send + Copy + 'static,
    listener: &TcpListener,
    conn: Connection,
) -> std::io::Result<()> {
    while let Ok((stream, _)) = listener.accept().await {
        if let Some(error) = conn.close_reason() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                error,
            ));
        }

        let conn = conn.clone();

        tokio::spawn(async move {
            match proxy.accept(stream).await {
                Ok(ProxyType::Tcp(mut stream)) => {
                    let target = stream.target_host().to_string();
                    start_tcp_tunnel(conn, &target, &mut stream)
                        .await
                        .inspect_err(|error| {
                            error!("tcp to {}, error: {}", target, error);
                        })
                        .ok();
                }
                Ok(ProxyType::Udp(_)) => {
                    error!("udp not implemented!");
                }
                Err(error) => {
                    error!("accept error: {}", error);
                }
            }
        });
    }

    Ok(())
}

#[derive(serde::Deserialize)]
struct Config {
    socks5_listen: String,
    http_listen: String,
    server_addr: String,
    server_name: String,
    server_cert: String,
}

fn main() {
    let mut args = env::args();
    if args.len() != 2 {
        println!("Usage: {} config.toml", args.nth(0).unwrap());
        return;
    }

    env_logger::builder()
        .format_timestamp(None)
        .filter_level(log::LevelFilter::Info)
        .parse_default_env()
        .init();
    info!("starting up");

    let content = String::from_utf8(fs::read(&args.nth(1).unwrap()).unwrap()).unwrap();
    let config: Config = toml::from_str(&content).unwrap();
    let rt = Runtime::new().unwrap();

    rt.block_on(async move {
        let socks5_listener = TcpListener::bind(config.socks5_listen).await.unwrap();
        let http_listener = TcpListener::bind(config.http_listen).await.unwrap();
        let addr = config.server_addr.parse().unwrap();
        let client_config = client::Config {
            addr: "0.0.0.0:0".to_string(),
            cert: config.server_cert,
        };

        loop {
            let endpoint = client::new(&client_config).unwrap();
            let conn = endpoint.connect(addr, &config.server_name).unwrap();

            match conn.await {
                Ok(conn) => {
                    let h = proxy(HttpProxy, &http_listener, conn.clone());
                    let s = proxy(Socks5Proxy, &socks5_listener, conn);

                    futures::try_join!(h, s)
                        .inspect_err(|error| {
                            error!("tunnel error: {}", error);
                        })
                        .ok();
                }
                Err(error) => {
                    error!("connect {} error: {}", addr, error);
                }
            }
        }
    });
}
