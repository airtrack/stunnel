#[macro_use]
extern crate log;

use stunnel::logger;
use stunnel::quic::server;
use tokio::runtime::Runtime;

fn main() {
    logger::init(log::Level::Info, "server.log".to_string(), 1, 2000000).unwrap();
    info!("starting up");

    let rt = Runtime::new().unwrap();

    rt.block_on(async move {
        let config = server::Config {
            addr: "0.0.0.0:12345".to_string(),
            cert: "stunnel_cert.pem".to_string(),
            priv_key: "private_key.pem".to_string(),
        };
        let endpoint = server::new(&config).unwrap();
        let incoming = endpoint.accept().await.unwrap();
        info!("accept quic incoming {}", incoming.remote_address());
        let conn = incoming.accept().unwrap().await.unwrap();
        info!("accept quic conn {}", conn.remote_address());
        let (_, _) = conn.accept_bi().await.unwrap();
        info!("accept quic bi");
        endpoint.wait_idle().await;
    });
}
