use std::{env, fs};

use log::{error, info};
use quinn::Connection;
use stunnel::{quic, tlstcp, tunnel::handle_tunnel};
use tokio::runtime::Runtime;

#[derive(serde::Deserialize, Clone)]
struct Config {
    listen: String,
    priv_key: String,
    cert: String,
}

async fn tlstcp_server(config: Config) -> std::io::Result<()> {
    let tlstcp_config = tlstcp::server::Config {
        addr: config.listen,
        cert: config.cert,
        priv_key: config.priv_key,
    };
    let acceptor = tlstcp::server::new(&tlstcp_config).await.unwrap();

    loop {
        let accepting = acceptor.accept().await?;

        tokio::spawn(async move {
            if let Ok(conn) = accepting.accept().await {
                let (mut reader, mut writer) = tlstcp::split(conn);
                handle_tunnel(&mut writer, &mut reader)
                    .await
                    .inspect_err(|error| {
                        error!("handle tlstcp tunnel error: {}", error);
                    })
                    .ok();
            }
        });
    }
}

async fn quic_server(config: Config) -> std::io::Result<()> {
    let quic_config = quic::server::Config {
        addr: config.listen,
        cert: config.cert,
        priv_key: config.priv_key,
    };
    let endpoint = quic::server::new(&quic_config).unwrap();

    loop {
        let incoming = endpoint.accept().await.ok_or(std::io::Error::new(
            std::io::ErrorKind::Other,
            "endpoint closed",
        ))?;

        tokio::spawn(async move {
            if let Ok(conn) = incoming.await {
                handle_quic_conn(conn)
                    .await
                    .inspect_err(|error| {
                        error!("handle quic conn error: {}", error);
                    })
                    .ok();
            }
        });
    }
}

async fn handle_quic_conn(conn: Connection) -> std::io::Result<()> {
    loop {
        let (mut send, mut recv) = conn.accept_bi().await?;

        tokio::spawn(async move {
            handle_tunnel(&mut send, &mut recv)
                .await
                .inspect_err(|error| {
                    error!("handle quic tunnel error: {}", error);
                })
                .ok();
        });
    }
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
        let t = tlstcp_server(config.clone());
        let q = quic_server(config);
        futures::try_join!(t, q).ok();
    });
}
