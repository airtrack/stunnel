use std::net::SocketAddr;
use std::{env, fs};

use log::{error, info};
use socks5::{AcceptResult, Address, UdpSocket, UdpSocketBuf, UdpSocketHolder};
use stunnel::tunnel::{
    AsyncReadDatagramExt, AsyncWriteDatagramExt, IntoTunnel, connect_tcp_tunnel, connect_udp_tunnel,
};
use stunnel::{quic, tlstcp};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Runtime;

trait State {
    fn in_good_condition(&mut self) -> std::io::Result<()>;
}

impl State for tlstcp::Connector {
    fn in_good_condition(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl State for quinn::Connection {
    fn in_good_condition(&mut self) -> std::io::Result<()> {
        if let Some(error) = self.close_reason() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                error,
            ));
        }

        Ok(())
    }
}

impl State for s2n_quic::connection::Handle {
    fn in_good_condition(&mut self) -> std::io::Result<()> {
        self.keep_alive(true)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::ConnectionReset, error))
    }
}

async fn tlstcp_client(
    config: Config,
    http_listener: TcpListener,
    socks5_listener: TcpListener,
) -> std::io::Result<()> {
    let tlstcp_config = tlstcp::client::Config {
        server_addr: config.server_addr,
        server_name: config.server_name,
        cert: config.server_cert,
        priv_key: config.private_key,
    };

    let connector = tlstcp::client::new(&tlstcp_config);
    let h = accept_http_tunnels(&http_listener, &connector);
    let s = accept_socks5_tunnels(&socks5_listener, &connector);

    futures::try_join!(h, s).map(|_| ())
}

async fn quinn_client(
    config: Config,
    http_listener: TcpListener,
    socks5_listener: TcpListener,
) -> std::io::Result<()> {
    let addr = config.server_addr.parse().unwrap();
    let client_config = quic::Config {
        addr: "0.0.0.0:0".to_string(),
        cert: config.server_cert,
        priv_key: config.private_key,
        loss_threshold: config.quic_loss_threshold,
    };

    loop {
        let endpoint = quic::quinn::client::new(&client_config).unwrap();
        let conn = endpoint.connect(addr, &config.server_name).unwrap();

        match conn.await {
            Ok(conn) => {
                let h = accept_http_tunnels(&http_listener, &conn);
                let s = accept_socks5_tunnels(&socks5_listener, &conn);

                futures::try_join!(h, s)
                    .inspect_err(|error| {
                        error!("tunnel error: {}", error);
                    })
                    .ok();
            }
            Err(error) => {
                error!("connect {} error: {}", addr, error);
            }
        }
    }
}

async fn s2n_client(
    config: Config,
    http_listener: TcpListener,
    socks5_listener: TcpListener,
) -> std::io::Result<()> {
    let addr: SocketAddr = config.server_addr.parse().unwrap();
    let client_config = quic::Config {
        addr: "0.0.0.0:0".to_string(),
        cert: config.server_cert,
        priv_key: config.private_key,
        loss_threshold: config.quic_loss_threshold,
    };

    loop {
        let endpoint = quic::s2n_quic::client::new(&client_config).unwrap();
        let connect =
            s2n_quic::client::Connect::new(addr).with_server_name(config.server_name.clone());
        let conn = endpoint.connect(connect);

        match conn.await {
            Ok(mut conn) => {
                if conn.keep_alive(true).is_ok() {
                    let conn = conn.handle();
                    let h = accept_http_tunnels(&http_listener, &conn);
                    let s = accept_socks5_tunnels(&socks5_listener, &conn);

                    futures::try_join!(h, s)
                        .inspect_err(|error| {
                            error!("tunnel error: {}", error);
                        })
                        .ok();
                }
            }
            Err(error) => {
                error!("connect {} error: {}", addr, error);
            }
        }
    }
}

async fn accept_http_tunnels<I, S, R>(listener: &TcpListener, into: &I) -> std::io::Result<()>
where
    I: IntoTunnel<S, R> + State + Clone + Send + 'static,
    S: AsyncWrite + Send + Unpin,
    R: AsyncRead + Send + Unpin,
{
    let mut into = into.clone();

    loop {
        let (stream, _) = listener.accept().await?;

        into.in_good_condition()?;
        let into = into.clone();

        tokio::spawn(async move {
            run_http_tunnel(stream, into)
                .await
                .inspect_err(|e| {
                    error!("http tunnel error: {}", e);
                })
                .ok();
        });
    }
}

async fn run_http_tunnel<I, S, R>(stream: TcpStream, into: I) -> std::io::Result<()>
where
    I: IntoTunnel<S, R> + State + Clone + Send + 'static,
    S: AsyncWrite + Send + Unpin,
    R: AsyncRead + Send + Unpin,
{
    let incoming = httpproxy::accept(stream).await?;

    match connect_tcp_tunnel(into, incoming.host()).await {
        Ok((_, mut tun)) => {
            let (mut stream, req) = incoming.response_200().await?;
            if let Some(req) = req {
                tun.write_all(&req).await?;
            }
            copy_bidirectional(&mut stream, &mut tun).await?;
        }
        Err(_) => {
            incoming.response_404().await?;
        }
    }

    Ok(())
}

async fn accept_socks5_tunnels<I, S, R>(listener: &TcpListener, into: &I) -> std::io::Result<()>
where
    I: IntoTunnel<S, R> + State + Clone + Send + 'static,
    S: AsyncWrite + Send + Unpin,
    R: AsyncRead + Send + Unpin,
{
    let mut into = into.clone();

    loop {
        let (stream, _) = listener.accept().await?;

        into.in_good_condition()?;
        let into = into.clone();

        tokio::spawn(async move {
            run_socks5_tunnel(stream, into)
                .await
                .inspect_err(|e| {
                    error!("socks5 tunnel error: {}", e);
                })
                .ok();
        });
    }
}

async fn run_socks5_tunnel<I, S, R>(stream: TcpStream, into: I) -> std::io::Result<()>
where
    I: IntoTunnel<S, R> + State + Clone + Send + 'static,
    S: AsyncWrite + Send + Unpin,
    R: AsyncRead + Send + Unpin,
{
    match socks5::accept(stream).await? {
        AcceptResult::Connect(incoming) => {
            let target = match incoming.destination() {
                Address::Host(host) => host,
                Address::Ip(addr) => &addr.to_string(),
            };

            match connect_tcp_tunnel(into, &target).await {
                Ok((bind, mut tun)) => {
                    let mut stream = incoming.reply_ok(bind).await?;
                    copy_bidirectional(&mut stream, &mut tun).await?;
                }
                Err(_) => {
                    incoming.reply_err().await?;
                }
            }
        }
        AcceptResult::UdpAssociate(incoming) => {
            let mut buf = UdpSocketBuf::new();
            let (socket, holder, dst) = incoming.recv_wait(&mut buf).await?;

            let tun = connect_udp_tunnel(into).await?;
            let (send, recv) = tun.split();

            async fn s<S>(
                socket: &UdpSocket,
                mut send: S,
                mut buf: UdpSocketBuf,
                addr: SocketAddr,
            ) -> std::io::Result<()>
            where
                S: AsyncWrite + Send + Unpin,
            {
                send.send_datagram(buf.as_ref(), addr).await?;
                loop {
                    let addr = socket.recv(&mut buf).await?;
                    send.send_datagram(buf.as_ref(), addr).await?;
                }
            }

            async fn r<R>(socket: &UdpSocket, mut recv: R) -> std::io::Result<()>
            where
                R: AsyncRead + Send + Unpin,
            {
                let mut buf = UdpSocketBuf::new();
                loop {
                    let (n, addr) = recv.recv_datagram(buf.as_mut()).await?;
                    buf.set_len(n);
                    socket.send(&mut buf, addr).await?;
                }
            }

            async fn h(mut holder: UdpSocketHolder) -> std::io::Result<()> {
                holder.wait().await
            }

            futures::try_join!(s(&socket, send, buf, dst), r(&socket, recv), h(holder))?;
        }
    }

    Ok(())
}

#[derive(serde::Deserialize)]
struct Config {
    socks5_listen: String,
    http_listen: String,
    server_addr: String,
    server_name: String,
    server_cert: String,
    private_key: String,
    tunnel_type: String,

    #[serde(default = "default_quic_loss_threshold")]
    quic_loss_threshold: u32,
}

fn default_quic_loss_threshold() -> u32 {
    20
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
        let socks5_listener = TcpListener::bind(&config.socks5_listen).await.unwrap();
        let http_listener = TcpListener::bind(&config.http_listen).await.unwrap();

        match config.tunnel_type.as_str() {
            "tlstcp" => {
                tlstcp_client(config, http_listener, socks5_listener)
                    .await
                    .ok();
            }
            "quic" => {
                quinn_client(config, http_listener, socks5_listener)
                    .await
                    .ok();
            }
            "s2n-quic" => {
                s2n_client(config, http_listener, socks5_listener)
                    .await
                    .ok();
            }
            _ => {
                panic!("unknown tunnel_type {}", config.tunnel_type);
            }
        }
    });
}
