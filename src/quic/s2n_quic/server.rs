use std::{error::Error, time::Duration};

use s2n_quic::{
    Server,
    provider::{congestion_controller::bbr, limits::Limits, tls},
};

use crate::quic::{Config, CongestionControl, s2n_quic::FixedBandwidthEndpoint};

pub fn new(config: &Config) -> std::io::Result<Server> {
    new_server(config)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::Other, error.to_string()))
}

fn new_server(config: &Config) -> Result<Server, Box<dyn Error>> {
    let limits = Limits::new()
        .with_max_open_local_bidirectional_streams(10000)?
        .with_max_open_remote_bidirectional_streams(10000)?
        .with_max_keep_alive_period(Duration::from_secs(3))?;

    let alpn: Vec<Vec<u8>> = vec![b"stunnel".to_vec()];
    let tls = tls::default::Server::builder()
        .with_application_protocols(alpn.iter())?
        .with_trusted_certificate(config.cert.as_path())?
        .with_certificate(config.cert.as_path(), config.priv_key.as_path())?
        .with_client_authentication()?
        .build()?;

    let server = match config.transport.cc {
        CongestionControl::Fixed => {
            let fixed_bandwidth = FixedBandwidthEndpoint {
                bandwidth: config.transport.fixed_bandwidth,
            };
            Server::builder()
                .with_tls(tls)?
                .with_io(config.addr)?
                .with_congestion_controller(fixed_bandwidth)?
                .with_limits(limits)?
                .start()?
        }
        CongestionControl::Bbr => {
            let bbr = bbr::Builder::default()
                .with_loss_threshold(config.transport.loss_threshold)
                .build();
            Server::builder()
                .with_tls(tls)?
                .with_io(config.addr)?
                .with_congestion_controller(bbr)?
                .with_limits(limits)?
                .start()?
        }
    };

    Ok(server)
}
