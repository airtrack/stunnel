use std::net::{AddrParseError, SocketAddr};

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
        _ => return std::io::Error::new(std::io::ErrorKind::Other, error.to_string()),
    })?;

    let priv_key = PrivateKeyDer::from_pem_file(&config.priv_key).map_err(|error| match error {
        pem::Error::Io(e) => return e,
        _ => return std::io::Error::new(std::io::ErrorKind::Other, error.to_string()),
    })?;

    let server_config = ServerConfig::with_single_cert(vec![cert], priv_key.into())
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::Other, error.to_string()))?;

    let addr: SocketAddr = config.addr.parse().map_err(|error: AddrParseError| {
        std::io::Error::new(std::io::ErrorKind::Other, error.to_string())
    })?;

    Endpoint::server(server_config, addr)
}
