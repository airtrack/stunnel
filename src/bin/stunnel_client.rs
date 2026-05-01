use std::{
    fs,
    net::SocketAddr,
    sync::atomic::{AtomicU64, AtomicUsize, Ordering},
    time::Instant,
};

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

static NEXT_TUNNEL_ID: AtomicU64 = AtomicU64::new(1);
static ACTIVE_HTTP_TUNNELS: AtomicUsize = AtomicUsize::new(0);
static ACTIVE_SOCKS5_TUNNELS: AtomicUsize = AtomicUsize::new(0);

trait IoErrorContext<T> {
    fn context(self, msg: &str) -> std::io::Result<T>;
}

impl<T> IoErrorContext<T> for std::io::Result<T> {
    fn context(self, msg: &str) -> std::io::Result<T> {
        self.map_err(|error| std::io::Error::new(error.kind(), format!("{msg}: {error}")))
    }
}

struct ActiveTunnelGuard {
    kind: &'static str,
    id: u64,
    active: &'static AtomicUsize,
    start: Instant,
}

impl ActiveTunnelGuard {
    fn new(kind: &'static str, active: &'static AtomicUsize) -> Self {
        let id = NEXT_TUNNEL_ID.fetch_add(1, Ordering::Relaxed);
        let active_count = active.fetch_add(1, Ordering::AcqRel) + 1;

        info!("{kind} proxy task started: tunnel={id} active={active_count}");

        Self {
            kind,
            id,
            active,
            start: Instant::now(),
        }
    }

    fn id(&self) -> u64 {
        self.id
    }
}

impl Drop for ActiveTunnelGuard {
    fn drop(&mut self) {
        let active_count = self.active.fetch_sub(1, Ordering::AcqRel) - 1;
        info!(
            "{} proxy task finished: tunnel={} elapsed={:?} active={}",
            self.kind,
            self.id,
            self.start.elapsed(),
            active_count
        );
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
                let id = conn.stable_id();
                let h = accept_http_tunnels(&http_listener, &conn, id);
                let s = accept_socks5_tunnels(&socks5_listener, &conn, id);
                let w = wait_conn_error(&conn);

                futures::try_join!(h, s, w)
                    .inspect_err(|error| {
                        error!("quic connection {id} broken: {error}");
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
        match acceptor.accept_bidirectional_stream().await {
            Ok(None) => Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "s2n-quic connection closed",
            )),
            Ok(Some(_)) => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "unexpected server-initiated stream",
            )),
            Err(error) => Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                error,
            )),
        }
    }

    loop {
        let connect =
            s2n_quic::client::Connect::new(addr).with_server_name(config.server_name.clone());

        match endpoint.connect(connect).await {
            Ok(mut conn) => {
                if conn.keep_alive(true).is_ok() {
                    let (conn, acceptor) = conn.split();
                    let id = conn.id();
                    let h = accept_http_tunnels(&http_listener, &conn, id);
                    let s = accept_socks5_tunnels(&socks5_listener, &conn, id);
                    let w = wait_conn_error(acceptor);

                    futures::try_join!(h, s, w)
                        .inspect_err(|error| {
                            error!("quic connection {id} broken: {error}");
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

async fn accept_http_tunnels<I, S, R, D>(
    listener: &TcpListener,
    into: &I,
    id: D,
) -> std::io::Result<()>
where
    I: IntoTunnel<S, R> + Clone + Send + 'static,
    S: AsyncWrite + Send + Unpin,
    R: AsyncRead + Send + Unpin,
    D: std::fmt::Display + Copy + Send + 'static,
{
    let into = into.clone();

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let guard = ActiveTunnelGuard::new("http", &ACTIVE_HTTP_TUNNELS);

        let id = id;
        let into = into.clone();
        let tunnel_id = guard.id();

        info!("http proxy accepted: tunnel={tunnel_id} underlying={id} peer={peer_addr}");

        tokio::spawn(async move {
            let _guard = guard;

            run_http_tunnel(stream, into, tunnel_id)
                .await
                .inspect_err(|error| {
                    error!(
                        "http proxy connection(on underlying {id}, tunnel {tunnel_id}) error: {error}"
                    );
                })
                .ok();
        });
    }
}

async fn run_http_tunnel<I, S, R>(stream: TcpStream, into: I, tunnel_id: u64) -> std::io::Result<()>
where
    I: IntoTunnel<S, R> + Clone + Send + 'static,
    S: AsyncWrite + Send + Unpin,
    R: AsyncRead + Send + Unpin,
{
    let incoming = httpproxy::accept(stream).await?;
    let host = incoming.host().to_string();

    info!("http proxy request: tunnel={tunnel_id} target={host}");

    match connect_tcp_tunnel(into, &host).await {
        Ok((_, mut tun)) => {
            info!("http tunnel connected: tunnel={tunnel_id} target={host}");
            let (mut stream, req) = incoming.response_200().await.context(&host)?;
            if let Some(req) = req {
                tun.write_all(&req).await.context(&host)?;
            }

            info!("http tunnel copy started: tunnel={tunnel_id} target={host}");
            let start = Instant::now();
            let (from_client, from_tunnel) = copy_bidirectional(&mut stream, &mut tun)
                .await
                .context(&host)?;
            info!(
                "http tunnel copy finished: tunnel={tunnel_id} target={host} elapsed={:?} from_client={} from_tunnel={}",
                start.elapsed(),
                from_client,
                from_tunnel
            );
        }
        Err(error) => {
            incoming.response_404().await.context(&host)?;
            return Err(error).context(&host);
        }
    }

    Ok(())
}

async fn accept_socks5_tunnels<I, S, R, D>(
    listener: &TcpListener,
    into: &I,
    id: D,
) -> std::io::Result<()>
where
    I: IntoTunnel<S, R> + Clone + Send + 'static,
    S: AsyncWrite + Send + Unpin,
    R: AsyncRead + Send + Unpin,
    D: std::fmt::Display + Copy + Send + 'static,
{
    let into = into.clone();

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let guard = ActiveTunnelGuard::new("socks5", &ACTIVE_SOCKS5_TUNNELS);

        let id = id;
        let into = into.clone();
        let tunnel_id = guard.id();

        info!("socks5 proxy accepted: tunnel={tunnel_id} underlying={id} peer={peer_addr}");

        tokio::spawn(async move {
            let _guard = guard;

            run_socks5_tunnel(stream, into, tunnel_id)
                .await
                .inspect_err(|error| {
                    error!(
                        "socks5 proxy connection(on underlying {id}, tunnel {tunnel_id}) error: {error}"
                    );
                })
                .ok();
        });
    }
}

async fn run_socks5_tunnel<I, S, R>(
    stream: TcpStream,
    into: I,
    tunnel_id: u64,
) -> std::io::Result<()>
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

            info!("socks5 connect request: tunnel={tunnel_id} target={target}");

            match connect_tcp_tunnel(into, &target).await {
                Ok((bind, mut tun)) => {
                    info!(
                        "socks5 tunnel connected: tunnel={tunnel_id} target={target} bind={bind}"
                    );
                    let mut stream = incoming.reply_ok(bind).await.context(&target)?;

                    info!("socks5 tunnel copy started: tunnel={tunnel_id} target={target}");
                    let start = Instant::now();
                    let (from_client, from_tunnel) = copy_bidirectional(&mut stream, &mut tun)
                        .await
                        .context(&target)?;
                    info!(
                        "socks5 tunnel copy finished: tunnel={tunnel_id} target={target} elapsed={:?} from_client={} from_tunnel={}",
                        start.elapsed(),
                        from_client,
                        from_tunnel
                    );
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

            info!("socks5 udp associate request: tunnel={tunnel_id} first_dst={dst}");

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

            info!("socks5 udp tunnel copy started: tunnel={tunnel_id} first_dst={dst}");
            futures::try_join!(s(&socket, send, buf, dst), r(&socket, recv), h(holder))?;
            info!("socks5 udp tunnel copy finished: tunnel={tunnel_id} first_dst={dst}");
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
