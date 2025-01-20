#[macro_use]
extern crate log;

use std::sync::Arc;

use quinn::Connection;
use stunnel::{
    proxy::socks5::{Socks5Proxy, Socks5TcpStream, Socks5UdpSocket},
    quic::client,
};
use tokio::{
    net::{TcpListener, TcpStream},
    runtime::Runtime,
};

async fn socks5_tcp(
    conn: Arc<Connection>,
    mut stream: Socks5TcpStream,
    host: &str,
) -> std::io::Result<(u64, u64)> {
    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_all(host.as_bytes()).await?;

    let mut buf = [0u8; 10];
    recv.read_exact(&mut buf)
        .await
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::Other, error))?;

    stream.connect_ok("0.0.0.0:0".parse().unwrap()).await?;
    stream.copy_bidirectional(&mut recv, &mut send).await
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
                Ok(Socks5Proxy::Connect { stream, host }) => {
                    let result = socks5_tcp(conn, stream, &host).await;
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
