use std::{
    net::{AddrParseError, SocketAddr},
    sync::Arc,
};

use quinn::{ClientConfig, Endpoint};
use rustls::pki_types::{
    pem::{self, PemObject},
    CertificateDer,
};

pub struct Config {
    pub addr: String,
    pub cert: String,
}

pub fn new(config: &Config) -> std::io::Result<Endpoint> {
    let cert = CertificateDer::from_pem_file(&config.cert).map_err(|error| match error {
        pem::Error::Io(e) => return e,
        _ => return std::io::Error::new(std::io::ErrorKind::Other, error.to_string()),
    })?;

    let mut certs = rustls::RootCertStore::empty();
    certs
        .add(cert)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::Other, error.to_string()))?;

    let client_config = ClientConfig::with_root_certificates(Arc::new(certs))
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::Other, error.to_string()))?;

    let addr: SocketAddr = config.addr.parse().map_err(|error: AddrParseError| {
        std::io::Error::new(std::io::ErrorKind::Other, error.to_string())
    })?;

    let mut endpoint = Endpoint::client(addr)?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}
