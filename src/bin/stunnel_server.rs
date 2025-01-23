use std::{env, fs};

use log::{error, info};
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

#[derive(serde::Deserialize)]
struct Config {
    listen: String,
    priv_key: String,
    cert: String,
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
        let server_config = server::Config {
            addr: config.listen,
            cert: config.cert,
            priv_key: config.priv_key,
        };
        let endpoint = server::new(&server_config).unwrap();

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
