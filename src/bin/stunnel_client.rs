use std::fs;
use std::net::SocketAddr;

use clap::Parser;
use log::{error, info};
use socks5::{AcceptResult, Address, UdpSocket, UdpSocketBuf, UdpSocketHolder};
use stunnel::tunnel::{
    AsyncReadDatagramExt, AsyncWriteDatagramExt,
    client::{IntoTunnel, connect_tcp_tunnel, connect_udp_tunnel},
};
use stunnel::{print_version, quic, tlstcp};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream};

trait IoErrorContext<T> {
    fn context(self, msg: &str) -> std::io::Result<T>;
}

impl<T> IoErrorContext<T> for std::io::Result<T> {
    fn context(self, msg: &str) -> std::io::Result<T> {
        self.map_err(|error| std::io::Error::new(error.kind(), format!("{msg}: {error}")))
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
    let h = accept_http_tunnels(&http_listener, &connector, "tlstcp");
    let s = accept_socks5_tunnels(&socks5_listener, &connector, "tlstcp");

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
        cc: config.quic.cc,
        loss_threshold: config.quic.loss_threshold,
        fixed_bandwidth: config.quic.fixed_bandwidth,
    };

    async fn wait_conn_error(conn: &quinn::Connection) -> std::io::Result<()> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            conn.closed().await,
        ))
    }

    loop {
        let endpoint = quic::quinn::client::new(&client_config).unwrap();
        let conn = endpoint.connect(addr, &config.server_name).unwrap();

        match conn.await {
            Ok(conn) => {
                let h = accept_http_tunnels(&http_listener, &conn, conn.stable_id());
                let s = accept_socks5_tunnels(&socks5_listener, &conn, conn.stable_id());
                let w = wait_conn_error(&conn);

                futures::try_join!(h, s, w)
                    .inspect_err(|error| {
                        error!("quic connection {} broken: {error}", conn.stable_id());
                    })
                    .ok();
            }
            Err(error) => {
                error!("quic connect error: {error}");
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
        cc: config.quic.cc,
        loss_threshold: config.quic.loss_threshold,
        fixed_bandwidth: config.quic.fixed_bandwidth,
    };

    let endpoint = quic::s2n_quic::client::new(&client_config).unwrap();

    async fn wait_conn_error(
        mut acceptor: s2n_quic::connection::StreamAcceptor,
    ) -> std::io::Result<()> {
        loop {
            match acceptor.accept().await {
                Ok(None) | Err(_) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionReset,
                        "connection closed",
                    ));
                }
                Ok(Some(_)) => {}
            }
        }
    }

    loop {
        let connect =
            s2n_quic::client::Connect::new(addr).with_server_name(config.server_name.clone());

        match endpoint.connect(connect).await {
            Ok(mut conn) => {
                if conn.keep_alive(true).is_ok() {
                    let (handle, acceptor) = conn.split();
                    let h = accept_http_tunnels(&http_listener, &handle, handle.id());
                    let s = accept_socks5_tunnels(&socks5_listener, &handle, handle.id());
                    let w = wait_conn_error(acceptor);

                    futures::try_join!(h, s, w)
                        .inspect_err(|error| {
                            error!("quic connection {} broken: {error}", handle.id());
                        })
                        .ok();
                }
            }
            Err(error) => {
                error!("quic connect error: {error}");
            }
        }
    }
}

async fn accept_http_tunnels<I, S, R, T>(
    listener: &TcpListener,
    into: &I,
    id: T,
) -> std::io::Result<()>
where
    I: IntoTunnel<S, R> + Clone + Send + 'static,
    S: AsyncWrite + Send + Unpin,
    R: AsyncRead + Send + Unpin,
    T: std::fmt::Display + Clone + Send + Copy + 'static,
{
    loop {
        let (stream, _) = listener.accept().await?;
        let into = into.clone();

        tokio::spawn(async move {
            run_http_tunnel(stream, into)
                .await
                .inspect_err(|error| {
                    error!("http proxy connection(over {id}) error: {error}");
                })
                .ok();
        });
    }
}

async fn run_http_tunnel<I, S, R>(stream: TcpStream, into: I) -> std::io::Result<()>
where
    I: IntoTunnel<S, R> + Clone + Send + 'static,
    S: AsyncWrite + Send + Unpin,
    R: AsyncRead + Send + Unpin,
{
    let incoming = httpproxy::accept(stream).await?;
    let host = incoming.host().to_string();

    match connect_tcp_tunnel(into, &host).await {
        Ok((_, mut tun)) => {
            let (mut stream, req) = incoming.response_200().await.context(&host)?;
            if let Some(req) = req {
                tun.write_all(&req).await.context(&host)?;
            }
            copy_bidirectional(&mut stream, &mut tun)
                .await
                .context(&host)?;
        }
        Err(error) => {
            incoming.response_404().await.context(&host)?;
            return Err(error).context(&host);
        }
    }

    Ok(())
}

async fn accept_socks5_tunnels<I, S, R, T>(
    listener: &TcpListener,
    into: &I,
    id: T,
) -> std::io::Result<()>
where
    I: IntoTunnel<S, R> + Clone + Send + 'static,
    S: AsyncWrite + Send + Unpin,
    R: AsyncRead + Send + Unpin,
    T: std::fmt::Display + Clone + Send + Copy + 'static,
{
    loop {
        let (stream, _) = listener.accept().await?;
        let into = into.clone();

        tokio::spawn(async move {
            run_socks5_tunnel(stream, into)
                .await
                .inspect_err(|error| {
                    error!("socks5 proxy connection(over {id}) error: {error}");
                })
                .ok();
        });
    }
}

async fn run_socks5_tunnel<I, S, R>(stream: TcpStream, into: I) -> std::io::Result<()>
where
    I: IntoTunnel<S, R> + Clone + Send + 'static,
    S: AsyncWrite + Send + Unpin,
    R: AsyncRead + Send + Unpin,
{
    match socks5::accept(stream).await? {
        AcceptResult::Connect(incoming) => {
            let target = match incoming.destination() {
                Address::Host(host) => host.clone(),
                Address::Ip(addr) => addr.to_string(),
            };

            match connect_tcp_tunnel(into, &target).await {
                Ok((bind, mut tun)) => {
                    let mut stream = incoming.reply_ok(bind).await.context(&target)?;
                    copy_bidirectional(&mut stream, &mut tun)
                        .await
                        .context(&target)?;
                }
                Err(error) => {
                    incoming.reply_err().await.context(&target)?;
                    return Err(error).context(&target);
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

#[derive(Parser)]
#[command(disable_version_flag = true)]
struct Args {
    #[arg(long, help = "Print version and build information")]
    version: bool,

    #[arg(
        long,
        value_name = "FILE",
        required_unless_present = "version",
        help = "Path to the client config file"
    )]
    config: Option<String>,
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

    #[serde(default)]
    quic: QuicConfig,

    #[cfg(target_os = "macos")]
    #[serde(default)]
    macos_logging: MacOsLogging,
}

#[derive(serde::Deserialize)]
struct QuicConfig {
    #[serde(default)]
    cc: String,
    loss_threshold: u32,
    #[serde(default)]
    fixed_bandwidth: u32,
}

impl Default for QuicConfig {
    fn default() -> Self {
        Self {
            cc: "bbr".to_string(),
            loss_threshold: 20,
            fixed_bandwidth: 6 * 1024 * 1024,
        }
    }
}

#[cfg(target_os = "macos")]
#[derive(serde::Deserialize, Default)]
struct MacOsLogging {
    enable: bool,
    subsystem: String,
}

fn init_log(_config: &Config) {
    #[cfg(target_os = "macos")]
    if _config.macos_logging.enable {
        oslog::OsLogger::new(&_config.macos_logging.subsystem)
            .level_filter(log::LevelFilter::Info)
            .category_level_filter("", log::LevelFilter::Info)
            .init()
            .unwrap();
        return;
    }

    env_logger::builder()
        .format_timestamp(None)
        .filter_level(log::LevelFilter::Info)
        .parse_default_env()
        .init();
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    if args.version {
        print_version("stunnel_client");
        return;
    }

    let config = args.config.unwrap();
    let content = String::from_utf8(fs::read(config).unwrap()).unwrap();
    let config: Config = toml::from_str(&content).unwrap();

    let socks5_listener = TcpListener::bind(&config.socks5_listen).await.unwrap();
    let http_listener = TcpListener::bind(&config.http_listen).await.unwrap();

    init_log(&config);
    info!("starting up");

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
}
