use clap::Parser;
use log::{error, info};
use stunnel::{
    config::{self, ClientConfig, ReverseProxyConfig, TunnelType},
    metrics::{TRANSPORT_ACTIVE_CONNECTIONS, TRANSPORT_CONNECTION_DURATION, TRANSPORT_CONNECTIONS},
    print_version, proxy, quic,
    telemetry::Telemetry,
    tlstcp,
    tunnel::client::ReverseTunnel,
    version,
};
use tokio::net::TcpListener;

async fn tlstcp_client(
    config: ClientConfig,
    http_listener: TcpListener,
    socks5_listener: TcpListener,
) -> std::io::Result<()> {
    let tlstcp_config = tlstcp::client::Config {
        server_addr: config.server_addr,
        server_name: config.server_name,
        cert: config.server_cert,
        priv_key: config.private_key,
    };

    let connector = tlstcp::client::new(&tlstcp_config)?;
    let h = proxy::accept_http_tunnels(&http_listener, &connector, "tlstcp");
    let s = proxy::accept_socks5_tunnels(&socks5_listener, &connector, "tlstcp");

    futures::try_join!(h, s).map(|_| ())
}

async fn quinn_client(
    config: ClientConfig,
    http_listener: TcpListener,
    socks5_listener: TcpListener,
) -> std::io::Result<()> {
    let reverse_tunnels = build_reverse_tunnels(&config.reverse_proxy);
    let client_config = quic::Config {
        addr: "0.0.0.0:0".parse().unwrap(),
        cert: config.server_cert,
        priv_key: config.private_key,
        transport: config.quic,
    };

    loop {
        let endpoint = quic::quinn::client::new(&client_config)?;
        let conn = endpoint
            .connect(config.server_addr, &config.server_name)
            .map_err(std::io::Error::other)?;

        match conn.await {
            Ok(conn) => {
                let id = conn.stable_id();
                let active = metrics::gauge!(TRANSPORT_ACTIVE_CONNECTIONS, "transport" => "quic");
                active.increment(1.0);
                metrics::counter!(TRANSPORT_CONNECTIONS, "transport" => "quic", "outcome" => "ok")
                    .increment(1);
                let started = std::time::Instant::now();

                proxy::run_all_kinds_tunnels(
                    conn.clone(),
                    conn,
                    &reverse_tunnels,
                    &http_listener,
                    &socks5_listener,
                    id,
                )
                .await
                .inspect_err(|error| {
                    error!("quic connection {id} broken: {error}");
                })
                .ok();

                active.decrement(1.0);
                metrics::histogram!(TRANSPORT_CONNECTION_DURATION, "transport" => "quic")
                    .record(started.elapsed().as_secs_f64());
            }
            Err(error) => {
                metrics::counter!(
                    TRANSPORT_CONNECTIONS,
                    "transport" => "quic",
                    "outcome" => "error",
                )
                .increment(1);
                error!("quic connect error: {error}");
            }
        }
    }
}

async fn s2n_client(
    config: ClientConfig,
    http_listener: TcpListener,
    socks5_listener: TcpListener,
) -> std::io::Result<()> {
    let reverse_tunnels = build_reverse_tunnels(&config.reverse_proxy);
    let client_config = quic::Config {
        addr: "0.0.0.0:0".parse().unwrap(),
        cert: config.server_cert,
        priv_key: config.private_key,
        transport: config.quic,
    };

    let endpoint = quic::s2n_quic::client::new(&client_config)?;

    loop {
        let connect = s2n_quic::client::Connect::new(config.server_addr)
            .with_server_name(config.server_name.clone());

        match endpoint.connect(connect).await {
            Ok(mut conn) => {
                if conn.keep_alive(true).is_ok() {
                    let id = conn.id();
                    let active =
                        metrics::gauge!(TRANSPORT_ACTIVE_CONNECTIONS, "transport" => "s2n-quic");
                    active.increment(1.0);
                    metrics::counter!(
                        TRANSPORT_CONNECTIONS,
                        "transport" => "s2n-quic",
                        "outcome" => "ok",
                    )
                    .increment(1);
                    let started = std::time::Instant::now();

                    let (opener, acceptor) = conn.split();
                    proxy::run_all_kinds_tunnels(
                        opener,
                        acceptor,
                        &reverse_tunnels,
                        &http_listener,
                        &socks5_listener,
                        id,
                    )
                    .await
                    .inspect_err(|error| {
                        error!("quic connection {id} broken: {error}");
                    })
                    .ok();

                    active.decrement(1.0);
                    metrics::histogram!(TRANSPORT_CONNECTION_DURATION, "transport" => "s2n-quic")
                        .record(started.elapsed().as_secs_f64());
                }
            }
            Err(error) => {
                metrics::counter!(
                    TRANSPORT_CONNECTIONS,
                    "transport" => "s2n-quic",
                    "outcome" => "error",
                )
                .increment(1);
                error!("quic connect error: {error}");
            }
        }
    }
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

fn build_reverse_tunnels(config: &[ReverseProxyConfig]) -> Vec<ReverseTunnel> {
    config
        .iter()
        .map(|config| ReverseTunnel {
            listen: config.listen,
            target: config.target,
        })
        .collect()
}

fn init_log(_config: &ClientConfig) {
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

    let config_path = args.config.unwrap();
    let config = match config::load_client(config_path) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("failed to load client config: {error}");
            return;
        }
    };

    let socks5_listener = TcpListener::bind(&config.socks5_listen)
        .await
        .expect("socks5 bind error");
    let http_listener = TcpListener::bind(&config.http_listen)
        .await
        .expect("http bind error");

    init_log(&config);
    info!("starting up");

    let _telemetry = match Telemetry::init(&config.otel, &version("stunnel_client")) {
        Ok(telemetry) => telemetry,
        Err(error) => {
            eprintln!("failed to start metrics: {error}");
            return;
        }
    };

    let result = match config.tunnel_type {
        TunnelType::TlsTcp => tlstcp_client(config, http_listener, socks5_listener).await,
        TunnelType::Quinn => quinn_client(config, http_listener, socks5_listener).await,
        TunnelType::S2nQuic => s2n_client(config, http_listener, socks5_listener).await,
    };

    if let Err(error) = result {
        eprintln!("stunnel client error: {error}");
    }
}
