use std::net::SocketAddr;
use std::{env, fs};

use log::{error, info};
use quinn::Connection;
use stunnel::{
    proxy::socks5::{Socks5Proxy, Socks5TcpStream, Socks5UdpSocket},
    quic::client,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    runtime::Runtime,
};

async fn socks5_tcp(
    conn: Connection,
    stream: &mut Socks5TcpStream,
    host: &str,
) -> std::io::Result<(u64, u64)> {
    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_u8(host.len() as u8).await?;
    send.write_all(host.as_bytes()).await?;

    let n = recv.read_u8().await? as usize;
    let mut buf = vec![0u8; n];
    recv.read_exact(&mut buf)
        .await
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::Other, error))?;

    if let Some(bind) = std::str::from_utf8(&buf)
        .ok()
        .and_then(|addr| addr.parse::<SocketAddr>().ok())
    {
        stream.connect_ok(bind).await?;
        stream.copy_bidirectional(&mut recv, &mut send).await
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid addr",
        ))
    }
}

async fn socks5_udp(
    _conn: Connection,
    _socket: Socks5UdpSocket,
    _holder: TcpStream,
) -> std::io::Result<()> {
    Ok(())
}

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
                    match socks5_tcp(conn, &mut stream, &host).await {
                        Ok(_) => {}
                        Err(error) => {
                            stream.connect_err().await.ok();
                            error!("tcp socks5 to {}, error: {}", host, error);
                        }
                    }
                }
                Ok(Socks5Proxy::UdpAssociate { socket, holder }) => {
                    socks5_udp(conn, socket, holder)
                        .await
                        .inspect_err(|error| {
                            error!("udp socks5 error: {}", error);
                        })
                        .ok();
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
