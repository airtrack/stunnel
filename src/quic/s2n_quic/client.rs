use std::{error::Error, path::Path, time::Duration};

use s2n_quic::{
    provider::{congestion_controller::bbr, limits::Limits, tls},
    Client,
};

use crate::quic::Config;

pub fn new(config: &Config) -> std::io::Result<Client> {
    new_client(config)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::Other, error.to_string()))
}

fn new_client(config: &Config) -> Result<Client, Box<dyn Error>> {
    let limits = Limits::new()
        .with_max_open_local_bidirectional_streams(10000)?
        .with_max_open_remote_bidirectional_streams(10000)?
        .with_max_keep_alive_period(Duration::from_secs(3))?;

    let alpn: Vec<Vec<u8>> = vec![b"stunnel".to_vec()];
    let tls = tls::default::Client::builder()
        .with_application_protocols(alpn.iter())?
        .with_certificate(Path::new(&config.cert))?
        .with_client_identity(Path::new(&config.cert), Path::new(&config.priv_key))?
        .build()?;

    let bbr = bbr::Builder::default()
        .with_loss_threshold(config.loss_threshold)
        .build();
    let client = Client::builder()
        .with_tls(tls)?
        .with_io(config.addr.as_str())?
        .with_congestion_controller(bbr)?
        .with_limits(limits)?
        .start()?;

    Ok(client)
}
