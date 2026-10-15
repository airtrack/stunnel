use clap::Parser;
use log::{error, info};
use quinn::Connection;
use stunnel::{
    config::{self, QuicBackend, ServerConfig},
    metrics::{TRANSPORT_ACTIVE_CONNECTIONS, TRANSPORT_CONNECTION_DURATION, TRANSPORT_CONNECTIONS},
    print_version, quic,
    telemetry::Telemetry,
    tlstcp,
    tunnel::server::{handle_all_kinds_tunnels, handle_forward_tunnel},
    version,
};

async fn tlstcp_server(config: ServerConfig) -> std::io::Result<()> {
    let tlstcp_config = tlstcp::server::Config {
        addr: config.listen,
        cert: config.cert,
        priv_key: config.priv_key,
    };
    let acceptor = tlstcp::server::new(&tlstcp_config).await?;

    loop {
        let accepting = acceptor.accept().await?;

        tokio::spawn(async move {
            if let Ok(conn) = accepting.accept().await {
                let active = metrics::gauge!(TRANSPORT_ACTIVE_CONNECTIONS, "transport" => "tlstcp");
                active.increment(1.0);
                metrics::counter!(
                    TRANSPORT_CONNECTIONS,
                    "transport" => "tlstcp",
                    "outcome" => "ok",
                )
                .increment(1);
                let started = std::time::Instant::now();

                let (mut reader, mut writer) = tlstcp::split(conn);
                handle_forward_tunnel(&mut writer, &mut reader)
                    .await
                    .inspect_err(|error| {
                        error!("handle tlstcp stream error: {error}");
                    })
                    .ok();

                active.decrement(1.0);
                metrics::histogram!(TRANSPORT_CONNECTION_DURATION, "transport" => "tlstcp")
                    .record(started.elapsed().as_secs_f64());
            }
        });
    }
}

async fn quinn_server(config: ServerConfig) -> std::io::Result<()> {
    let quic_config = quic::Config {
        addr: config.listen,
        cert: config.cert,
        priv_key: config.priv_key,
        transport: config.quic.transport,
    };
    let endpoint = quic::quinn::server::new(&quic_config)?;

    loop {
        let incoming = endpoint
            .accept()
            .await
            .ok_or(std::io::Error::other("endpoint closed"))?;

        tokio::spawn(async move {
            if let Ok(conn) = incoming.await {
                let active = metrics::gauge!(TRANSPORT_ACTIVE_CONNECTIONS, "transport" => "quic");
                active.increment(1.0);
                metrics::counter!(TRANSPORT_CONNECTIONS, "transport" => "quic", "outcome" => "ok")
                    .increment(1);
                let started = std::time::Instant::now();

                handle_quinn_conn(conn)
                    .await
                    .inspect_err(|error| {
                        error!("handle quic conn error: {error}");
                    })
                    .ok();

                active.decrement(1.0);
                metrics::histogram!(TRANSPORT_CONNECTION_DURATION, "transport" => "quic")
                    .record(started.elapsed().as_secs_f64());
            }
        });
    }
}

async fn handle_quinn_conn(conn: Connection) -> std::io::Result<()> {
    handle_all_kinds_tunnels(conn.clone(), conn).await
}

async fn s2n_server(config: ServerConfig) -> std::io::Result<()> {
    let quic_config = quic::Config {
        addr: config.listen,
        cert: config.cert,
        priv_key: config.priv_key,
        transport: config.quic.transport,
    };
    let mut endpoint = quic::s2n_quic::server::new(&quic_config)?;

    loop {
        let conn = endpoint
            .accept()
            .await
            .ok_or(std::io::Error::other("endpoint closed"))?;

        tokio::spawn(async move {
            let active = metrics::gauge!(TRANSPORT_ACTIVE_CONNECTIONS, "transport" => "s2n-quic");
            active.increment(1.0);
            metrics::counter!(
                TRANSPORT_CONNECTIONS,
                "transport" => "s2n-quic",
                "outcome" => "ok",
            )
            .increment(1);
            let started = std::time::Instant::now();

            handle_s2n_conn(conn)
                .await
                .inspect_err(|error| {
                    error!("handle quic conn error: {error}");
                })
                .ok();

            active.decrement(1.0);
            metrics::histogram!(TRANSPORT_CONNECTION_DURATION, "transport" => "s2n-quic")
                .record(started.elapsed().as_secs_f64());
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

    let config_path = args.config.unwrap();
    let config = match config::load_server(config_path) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("failed to load server config: {error}");
            return;
        }
    };

    let _telemetry = match Telemetry::init(&config.otel, &version("stunnel_server")) {
        Ok(telemetry) => telemetry,
        Err(error) => {
            eprintln!("failed to start metrics: {error}");
            return;
        }
    };

    let result = match config.quic.server_type {
        QuicBackend::S2nQuic => {
            let t = tlstcp_server(config.clone());
            let q = s2n_server(config);
            futures::try_join!(t, q).map(|_| ())
        }
        QuicBackend::Quinn => {
            let t = tlstcp_server(config.clone());
            let q = quinn_server(config);
            futures::try_join!(t, q).map(|_| ())
        }
    };

    if let Err(error) = result {
        eprintln!("stunnel server error: {error}");
    }
}
