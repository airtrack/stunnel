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

async fn socks5(conn: Arc<Connection>) -> std::io::Result<()> {
    let listener = TcpListener::bind("0.0.0.0:21080").await.unwrap();

    while let Ok((stream, _)) = listener.accept().await {
        let conn = conn.clone();

        tokio::spawn(async move {
            match Socks5Proxy::accept(stream).await {
                Ok(Socks5Proxy::Connect { mut stream, host }) => {
                    let result = socks5_tcp(conn, &mut stream, &host).await;
                    if result.is_err() {
                        stream.connect_err().await.ok();
                    }
                    info!("tcp socks5 to {}, result: {:?}", host, result);
                }
                Ok(Socks5Proxy::UdpAssociate { socket, holder }) => {
                    let result = socks5_udp(conn, socket, holder).await;
                    info!("udp socks5, result: {:?}", result);
                }
                Err(_) => {}
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
        let config = client::Config {
            addr: "0.0.0.0:0".to_string(),
            cert: "stunnel_cert.pem".to_string(),
        };
        let endpoint = client::new(&config).unwrap();
        let conn = endpoint
            .connect("127.0.0.1:12345".parse().unwrap(), "stunnel")
            .unwrap()
            .await
            .unwrap();

        socks5(Arc::new(conn)).await.unwrap();
    });
}
