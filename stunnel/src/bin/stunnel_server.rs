use std::{env, fs};

use log::{error, info};
use quinn::Connection;
use stunnel::{
    quic, tlstcp,
    tunnel::{Incoming, accept, copy_bidirectional_udp_socket},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, copy_bidirectional},
    net::{TcpStream, UdpSocket},
    runtime::Runtime,
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
                handle_tunnel(&mut writer, &mut reader)
                    .await
                    .inspect_err(|error| {
                        error!("handle tlstcp stream error: {}", error);
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
        loss_threshold: config.quic_loss_threshold,
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
                        error!("handle quic conn error: {}", error);
                    })
                    .ok();
            }
        });
    }
}

async fn handle_quinn_conn(conn: Connection) -> std::io::Result<()> {
    loop {
        let (mut send, mut recv) = conn.accept_bi().await?;

        tokio::spawn(async move {
            handle_tunnel(&mut send, &mut recv)
                .await
                .inspect_err(|error| {
                    error!("handle quic stream error: {}", error);
                })
                .ok();
        });
    }
}

async fn s2n_server(config: Config) -> std::io::Result<()> {
    let quic_config = quic::Config {
        addr: config.listen,
        cert: config.cert,
        priv_key: config.priv_key,
        loss_threshold: config.quic_loss_threshold,
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
                    error!("handle quic conn error: {}", error);
                })
                .ok();
        });
    }
}

async fn handle_s2n_conn(mut conn: s2n_quic::Connection) -> std::io::Result<()> {
    loop {
        let stream = conn
            .accept_bidirectional_stream()
            .await?
            .ok_or(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "conn closed",
            ))?;
        let (mut recv, mut send) = stream.split();

        tokio::spawn(async move {
            handle_tunnel(&mut send, &mut recv)
                .await
                .inspect_err(|error| {
                    error!("handle quic stream error: {}", error);
                })
                .ok();
        });
    }
}

async fn handle_tunnel<S, R>(send: S, recv: R) -> std::io::Result<(u64, u64)>
where
    S: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    match accept(send, recv).await? {
        Incoming::UdpTunnel(mut tun) => {
            let socket = UdpSocket::bind("0.0.0.0:0").await?;
            tun.response(socket.local_addr()?).await?;
            copy_bidirectional_udp_socket(tun, &socket).await
        }
        Incoming::TcpTunnel((mut tun, destination)) => {
            let mut stream = TcpStream::connect(destination).await?;
            tun.response(stream.local_addr()?).await?;
            copy_bidirectional(&mut tun, &mut stream).await
        }
    }
}

#[derive(serde::Deserialize, Clone)]
struct Config {
    listen: String,
    priv_key: String,
    cert: String,

    #[serde(default = "default_quic_server")]
    quic_server: String,
    #[serde(default = "default_quic_loss_threshold")]
    quic_loss_threshold: u32,
}

fn default_quic_loss_threshold() -> u32 {
    20
}

fn default_quic_server() -> String {
    "s2n-quic".to_string()
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
        match config.quic_server.as_str() {
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
    });
}
