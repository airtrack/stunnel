use std::{env, fs};

use log::{error, info};
use quinn::Connection;
use stunnel::{quic::server, tunnel::handle_tunnel};
use tokio::runtime::Runtime;

async fn handle_conn(conn: Connection) -> std::io::Result<()> {
    loop {
        let (mut send, mut recv) = conn.accept_bi().await?;
        tokio::spawn(async move {
            handle_tunnel(&mut send, &mut recv)
                .await
                .inspect_err(|error| {
                    error!("handle tunnel error: {}", error);
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
