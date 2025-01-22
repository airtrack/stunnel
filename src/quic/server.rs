use std::{net::SocketAddr, sync::Arc};

use quinn::{Endpoint, ServerConfig};
use rustls::pki_types::{
    pem::{self, PemObject},
    CertificateDer, PrivateKeyDer,
};

pub struct Config {
    pub addr: String,
    pub cert: String,
    pub priv_key: String,
}

pub fn new(config: &Config) -> std::io::Result<Endpoint> {
    let cert = CertificateDer::from_pem_file(&config.cert).map_err(|error| match error {
        pem::Error::Io(e) => return e,
        _ => return std::io::Error::new(std::io::ErrorKind::Other, error),
    })?;

    let priv_key = PrivateKeyDer::from_pem_file(&config.priv_key).map_err(|error| match error {
        pem::Error::Io(e) => return e,
        _ => return std::io::Error::new(std::io::ErrorKind::Other, error),
    })?;

    let mut server_config = ServerConfig::with_single_cert(vec![cert], priv_key.into())
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::Other, error))?;
    let transport = Arc::get_mut(&mut server_config.transport).unwrap();
    transport.max_concurrent_bidi_streams(10000u32.into());

    let addr = config
        .addr
        .parse::<SocketAddr>()
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::Other, error))?;

    Endpoint::server(server_config, addr)
}
