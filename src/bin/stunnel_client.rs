#[macro_use]
extern crate log;

use std::{net::SocketAddr, sync::Arc};

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
    conn: Arc<Connection>,
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
    _conn: Arc<Connection>,
    _socket: Socks5UdpSocket,
    _holder: TcpStream,
) -> std::io::Result<()> {
    Ok(())
}

async fn socks5(listener: &TcpListener, conn: Arc<Connection>) -> std::io::Result<()> {
    while let Ok((stream, _)) = listener.accept().await {
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

fn main() {
    env_logger::builder()
        .format_timestamp(None)
        .filter_level(log::LevelFilter::Info)
        .parse_default_env()
        .init();
    info!("starting up");

    let rt = Runtime::new().unwrap();

    rt.block_on(async move {
        let listener = TcpListener::bind("0.0.0.0:21080").await.unwrap();
        let addr = "127.0.0.1:12345".parse().unwrap();
        let config = client::Config {
            addr: "0.0.0.0:0".to_string(),
            cert: "stunnel_cert.pem".to_string(),
        };

        loop {
            let endpoint = client::new(&config).unwrap();
            let conn = endpoint.connect(addr, "stunnel").unwrap();

            match conn.await {
                Ok(conn) => {
                    socks5(&listener, Arc::new(conn))
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
