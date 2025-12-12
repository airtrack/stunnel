use std::{env, fs};

use log::{error, info};
use quinn::Connection;
use stunnel::{
    quic, tlstcp,
    tunnel::{
        AsyncReadDatagramExt, AsyncWriteDatagramExt, Tunnel,
        server::{Incoming, accept},
    },
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
        loss_threshold: config.quic.loss_threshold,
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
        loss_threshold: config.quic.loss_threshold,
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
    S: AsyncWrite + Send + Unpin,
    R: AsyncRead + Send + Unpin,
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

async fn copy_bidirectional_udp_socket<S, R>(
    tun: Tunnel<S, R>,
    socket: &UdpSocket,
) -> std::io::Result<(u64, u64)>
where
    S: AsyncWrite + Send + Unpin,
    R: AsyncRead + Send + Unpin,
{
    async fn r<S>(socket: &UdpSocket, send: &mut S) -> std::io::Result<()>
    where
        S: AsyncWrite + Send + Unpin,
    {
        let mut buf = [0u8; 1500];
        loop {
            let (n, from) = socket.recv_from(&mut buf).await?;
            send.send_datagram(&buf[..n], from).await?;
        }
    }

    async fn w<R>(socket: &UdpSocket, recv: &mut R) -> std::io::Result<()>
    where
        R: AsyncRead + Send + Unpin,
    {
        let mut buf = [0u8; 1500];
        loop {
            let (n, target) = recv.recv_datagram(&mut buf).await?;
            socket.send_to(&buf[..n], target).await?;
        }
    }

    let (mut send, mut recv) = tun.split();
    futures::try_join!(r(socket, &mut send), w(socket, &mut recv)).map(|_| (0, 0))
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
    loss_threshold: u32,
}

impl Default for QuicConfig {
    fn default() -> Self {
        Self {
            server_type: "s2n-quic".to_string(),
            loss_threshold: 20,
        }
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
    });
}
