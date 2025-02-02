use std::{env, fs};

use log::{error, info};
use quinn::Connection;
use stunnel::tunnel::handle_socks5_tcp;
use stunnel::{proxy::socks5::Socks5Proxy, quic::client};
use tokio::{net::TcpListener, runtime::Runtime};

async fn socks5(listener: &TcpListener, conn: Connection) -> std::io::Result<()> {
    while let Ok((stream, _)) = listener.accept().await {
        if let Some(error) = conn.close_reason() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                error,
            ));
        }

        let conn = conn.clone();

        tokio::spawn(async move {
            match Socks5Proxy::accept(stream).await {
                Ok(Socks5Proxy::Connect { mut stream, host }) => {
                    handle_socks5_tcp(conn, &host, &mut stream)
                        .await
                        .inspect_err(|error| {
                            error!("tcp socks5 to {}, error: {}", host, error);
                        })
                        .ok();
                }
                Ok(_) => {
                    error!("socks5 udp not implemented!");
                }
                Err(error) => {
                    error!("socks5 accept error: {}", error);
                }
            }
        });
    }

    Ok(())
}

#[derive(serde::Deserialize)]
struct Config {
    socks5_listen: String,
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
        let listener = TcpListener::bind(config.socks5_listen).await.unwrap();
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
                    socks5(&listener, conn)
                        .await
                        .inspect_err(|error| {
                            error!("socks5 error: {}", error);
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
