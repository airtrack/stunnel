#[macro_use]
extern crate log;

use stunnel::quic::client;
use tokio::runtime::Runtime;

fn main() {
    env_logger::builder()
        .format_timestamp(None)
        .filter_level(log::LevelFilter::Info)
        .parse_default_env()
        .init();
    info!("starting up");

    let rt = Runtime::new().unwrap();

    rt.block_on(async move {
        let config = client::Config {
            addr: "0.0.0.0:0".to_string(),
            cert: "stunnel_cert.pem".to_string(),
        };
        let endpoint = client::new(&config).unwrap();
        let conn = endpoint
            .connect("127.0.0.1:12345".parse().unwrap(), "stunnel")
            .unwrap()
            .await
            .unwrap();
        info!("connect quic server success.");
        let (_, _) = conn.open_bi().await.unwrap();
        info!("open quic stream success.");
        endpoint.wait_idle().await;
    });
}
