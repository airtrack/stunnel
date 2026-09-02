use std::{error::Error, sync::Arc, time::Duration};

use quinn::{ClientConfig, Endpoint, TransportConfig, crypto::rustls::QuicClientConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};

use crate::quic::Config;

use super::cc_factory;

pub fn new(config: &Config) -> std::io::Result<Endpoint> {
    new_client(config)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::Other, error.to_string()))
}

fn new_client(config: &Config) -> Result<Endpoint, Box<dyn Error>> {
    let cert = CertificateDer::from_pem_file(&config.cert)?;
    let priv_key = PrivateKeyDer::from_pem_file(&config.priv_key)?;

    let mut certs = rustls::RootCertStore::empty();
    certs.add(cert.clone())?;

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut client_config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(certs)
        .with_client_auth_cert(vec![cert], priv_key)?;
    client_config.enable_early_data = true;
    client_config.alpn_protocols = vec![b"stunnel".to_vec()];

    let client_config = QuicClientConfig::try_from(client_config)?;
    let mut client_config = ClientConfig::new(Arc::new(client_config));

    let mut transport = TransportConfig::default();
    transport
        .max_concurrent_bidi_streams(10000u32.into())
        .keep_alive_interval(Some(Duration::from_secs(3)))
        .congestion_controller_factory(cc_factory(config));

    client_config.transport_config(Arc::new(transport));

    let mut endpoint = Endpoint::client(config.addr)?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}
