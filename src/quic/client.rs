use std::{
    net::{AddrParseError, SocketAddr},
    sync::Arc,
    time::Duration,
};

use quinn::{ClientConfig, Endpoint, TransportConfig};
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
        _ => return std::io::Error::new(std::io::ErrorKind::Other, error),
    })?;

    let mut certs = rustls::RootCertStore::empty();
    certs
        .add(cert)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::Other, error))?;

    let mut client_config = ClientConfig::with_root_certificates(Arc::new(certs))
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::Other, error))?;
    let mut transport = TransportConfig::default();
    transport
        .max_concurrent_bidi_streams(10000u32.into())
        .keep_alive_interval(Some(Duration::from_secs(3)));
    client_config.transport_config(Arc::new(transport));

    let addr: SocketAddr = config
        .addr
        .parse()
        .map_err(|error: AddrParseError| std::io::Error::new(std::io::ErrorKind::Other, error))?;

    let mut endpoint = Endpoint::client(addr)?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}
