use std::{env, fs};

use log::{error, info};
use stunnel::proxy::{http::HttpProxy, socks5::Socks5Proxy};
use stunnel::proxy::{
    AsyncReadDatagram, AsyncWriteDatagram, Proxy, ProxyType, TcpProxyConn, UdpProxyBind,
};
use stunnel::tunnel::{start_tcp_tunnel, start_udp_tunnel, IntoTunnel};
use stunnel::{quic, tlstcp};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::{net::TcpListener, runtime::Runtime};

trait State {
    fn in_good_condition(&self) -> std::io::Result<()>;
}

impl State for tlstcp::Connector {
    fn in_good_condition(&self) -> std::io::Result<()> {
        Ok(())
    }
}

impl State for quinn::Connection {
    fn in_good_condition(&self) -> std::io::Result<()> {
        if let Some(error) = self.close_reason() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                error,
            ));
        }

        Ok(())
    }
}

async fn tlstcp_client(
    config: Config,
    http_listener: TcpListener,
    socks5_listener: TcpListener,
) -> std::io::Result<()> {
    let tlstcp_config = tlstcp::client::Config {
        server_addr: config.server_addr,
        server_name: config.server_name,
        cert: config.server_cert,
        priv_key: config.private_key,
    };

    let connector = tlstcp::client::new(&tlstcp_config);
    let h = proxy_tunnel(HttpProxy, &connector, &http_listener);
    let s = proxy_tunnel(Socks5Proxy, &connector, &socks5_listener);

    futures::try_join!(h, s).map(|_| ())
}

async fn quic_client(
    config: Config,
    http_listener: TcpListener,
    socks5_listener: TcpListener,
) -> std::io::Result<()> {
    let addr = config.server_addr.parse().unwrap();
    let client_config = quic::client::Config {
        addr: "0.0.0.0:0".to_string(),
        cert: config.server_cert,
    };

    loop {
        let endpoint = quic::client::new(&client_config).unwrap();
        let conn = endpoint.connect(addr, &config.server_name).unwrap();

        match conn.await {
            Ok(conn) => {
                let h = proxy_tunnel(HttpProxy, &conn, &http_listener);
                let s = proxy_tunnel(Socks5Proxy, &conn, &socks5_listener);

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
}

async fn proxy_tunnel<
    T: TcpProxyConn + Send,
    U: UdpProxyBind + Send,
    S: AsyncWriteDatagram + AsyncWrite + Send + Unpin,
    R: AsyncReadDatagram + AsyncRead + Send + Unpin,
>(
    proxy: impl Proxy<T, U> + Sync + Send + Copy + 'static,
    into: &(impl IntoTunnel<S, R> + State + Clone + Send + 'static),
    listener: &TcpListener,
) -> std::io::Result<()> {
    while let Ok((stream, _)) = listener.accept().await {
        into.in_good_condition()?;
        let into = into.clone();

        tokio::spawn(async move {
            match proxy.accept(stream).await {
                Ok(ProxyType::Tcp(mut tcp)) => {
                    let target = tcp.target_host().to_string();
                    start_tcp_tunnel(into, &target, &mut tcp)
                        .await
                        .inspect_err(|error| {
                            error!("tcp to {}, error: {}", target, error);
                        })
                        .ok();
                }
                Ok(ProxyType::Udp(udp)) => {
                    start_udp_tunnel(into, udp)
                        .await
                        .inspect_err(|error| {
                            error!("udp bind error: {}", error);
                        })
                        .ok();
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
    private_key: String,
    tunnel_type: String,
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
        let socks5_listener = TcpListener::bind(&config.socks5_listen).await.unwrap();
        let http_listener = TcpListener::bind(&config.http_listen).await.unwrap();

        match config.tunnel_type.as_str() {
            "tlstcp" => {
                tlstcp_client(config, http_listener, socks5_listener)
                    .await
                    .ok();
            }
            "quic" => {
                quic_client(config, http_listener, socks5_listener)
                    .await
                    .ok();
            }
            _ => {
                panic!("unknown tunnel_type {}", config.tunnel_type);
            }
        }
    });
}
