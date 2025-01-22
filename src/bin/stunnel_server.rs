#[macro_use]
extern crate log;

use quinn::{Connection, RecvStream, SendStream};
use stunnel::{proxy::copy_bidirectional, quic::server};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    runtime::Runtime,
};

async fn handle_stream(mut send: SendStream, mut recv: RecvStream) -> std::io::Result<(u64, u64)> {
    let n = recv.read_u8().await? as usize;
    let mut buf = vec![0u8; n];
    recv.read_exact(&mut buf)
        .await
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::Other, error))?;

    if let Some(addr) = std::str::from_utf8(&buf).ok() {
        let mut stream = TcpStream::connect(addr).await?;
        let addr = stream.local_addr()?.to_string();
        send.write_u8(addr.len() as u8).await?;
        send.write_all(addr.as_bytes()).await?;
        copy_bidirectional(&mut stream, &mut recv, &mut send).await
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid addr",
        ))
    }
}

async fn handle_conn(conn: Connection) -> std::io::Result<()> {
    loop {
        let (send, recv) = conn.accept_bi().await?;
        tokio::spawn(async move {
            handle_stream(send, recv)
                .await
                .inspect_err(|error| {
                    error!("handle stream error: {}", error);
                })
                .ok();
        });
    }
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
        let config = server::Config {
            addr: "0.0.0.0:12345".to_string(),
            cert: "stunnel_cert.pem".to_string(),
            priv_key: "private_key.pem".to_string(),
        };
        let endpoint = server::new(&config).unwrap();

        while let Some(incoming) = endpoint.accept().await {
            tokio::spawn(async move {
                if let Ok(conn) = incoming.await {
                    handle_conn(conn)
                        .await
                        .inspect_err(|error| {
                            error!("handle conn error: {}", error);
                        })
                        .ok();
                }
            });
        }
    });
}
