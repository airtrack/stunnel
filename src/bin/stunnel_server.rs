use std::fs;

use clap::Parser;
use log::{error, info};
use quinn::Connection;
use stunnel::{
    print_version, quic, tlstcp,
    tunnel::server::{handle_all_kinds_tunnels, handle_forward_tunnel},
};

async fn tlstcp_server(config: Config) -> std::io::Result<()> {
    let tlstcp_config = tlstcp::server::Config {
        addr: config.listen,
        cert: config.cert,
        priv_key: config.priv_key,
    };
    let acceptor = tlstcp::server::new(&tlstcp_config).await;

    loop {
        let accepting = acceptor.accept().await?;

        tokio::spawn(async move {
            if let Ok(conn) = accepting.accept().await {
                let (mut reader, mut writer) = tlstcp::split(conn);
                handle_forward_tunnel(&mut writer, &mut reader)
                    .await
                    .inspect_err(|error| {
                        error!("handle tlstcp stream error: {error}");
                    })
                    .ok();
            }
        });
    }
}

async fn quinn_server(config: Config) -> std::io::Result<()> {
    let quic_config = quic::Config {
        addr: config.listen,
        cert: config.cert,
        priv_key: config.priv_key,
        cc: config.quic.cc,
        loss_threshold: config.quic.loss_threshold,
        fixed_bandwidth: config.quic.fixed_bandwidth,
    };
    let endpoint = quic::quinn::server::new(&quic_config).unwrap();

    loop {
        let incoming = endpoint.accept().await.ok_or(std::io::Error::new(
            std::io::ErrorKind::Other,
            "endpoint closed",
        ))?;

        tokio::spawn(async move {
            if let Ok(conn) = incoming.await {
                handle_quinn_conn(conn)
                    .await
                    .inspect_err(|error| {
                        error!("handle quic conn error: {error}");
                    })
                    .ok();
            }
        });
    }
}

async fn handle_quinn_conn(conn: Connection) -> std::io::Result<()> {
    handle_all_kinds_tunnels(conn.clone(), conn).await
}

async fn s2n_server(config: Config) -> std::io::Result<()> {
    let quic_config = quic::Config {
        addr: config.listen,
        cert: config.cert,
        priv_key: config.priv_key,
        cc: config.quic.cc,
        loss_threshold: config.quic.loss_threshold,
        fixed_bandwidth: config.quic.fixed_bandwidth,
    };
    let mut endpoint = quic::s2n_quic::server::new(&quic_config).unwrap();

    loop {
        let conn = endpoint.accept().await.ok_or(std::io::Error::new(
            std::io::ErrorKind::Other,
            "endpoint closed",
        ))?;

        tokio::spawn(async move {
            handle_s2n_conn(conn)
                .await
                .inspect_err(|error| {
                    error!("handle quic conn error: {error}");
                })
                .ok();
        });
    }
}

async fn handle_s2n_conn(conn: s2n_quic::Connection) -> std::io::Result<()> {
    let (conn, acceptor) = conn.split();
    handle_all_kinds_tunnels(conn, acceptor).await
}

#[derive(Parser)]
#[command(disable_version_flag = true)]
struct Args {
    #[arg(long, help = "Print version and build information")]
    version: bool,

    #[arg(
        long,
        value_name = "FILE",
        required_unless_present = "version",
        help = "Path to the server config file"
    )]
    config: Option<String>,
}

#[derive(serde::Deserialize, Clone)]
struct Config {
    listen: String,
    priv_key: String,
    cert: String,

    #[serde(default)]
    quic: QuicConfig,
}

#[derive(serde::Deserialize, Clone)]
struct QuicConfig {
    server_type: String,
    #[serde(default)]
    cc: String,
    loss_threshold: u32,
    #[serde(default)]
    fixed_bandwidth: u32,
}

impl Default for QuicConfig {
    fn default() -> Self {
        Self {
            server_type: "s2n-quic".to_string(),
            cc: "bbr".to_string(),
            loss_threshold: 20,
            fixed_bandwidth: 6 * 1024 * 1024,
        }
    }
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    if args.version {
        print_version("stunnel_server");
        return;
    }

    env_logger::builder()
        .format_timestamp(None)
        .filter_level(log::LevelFilter::Info)
        .parse_default_env()
        .init();
    info!("starting up");

    let config = args.config.unwrap();
    let content = String::from_utf8(fs::read(config).unwrap()).unwrap();
    let config: Config = toml::from_str(&content).unwrap();

    match config.quic.server_type.as_str() {
        "s2n-quic" => {
            let t = tlstcp_server(config.clone());
            let q = s2n_server(config);
            futures::try_join!(t, q).ok();
        }
        "quic" | _ => {
            let t = tlstcp_server(config.clone());
            let q = quinn_server(config);
            futures::try_join!(t, q).ok();
        }
    }
}
