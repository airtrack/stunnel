use std::{error::Error, sync::Arc};

use quinn::{Endpoint, ServerConfig, crypto::rustls::QuicServerConfig};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    server::WebPkiClientVerifier,
};

use crate::quic::Config;

use super::cc_factory;

pub fn new(config: &Config) -> std::io::Result<Endpoint> {
    new_server(config).map_err(std::io::Error::other)
}

fn new_server(config: &Config) -> Result<Endpoint, Box<dyn Error + Send + Sync>> {
    let cert = CertificateDer::from_pem_file(&config.cert)?;
    let priv_key = PrivateKeyDer::from_pem_file(&config.priv_key)?;

    let mut certs = rustls::RootCertStore::empty();
    certs.add(cert.clone())?;

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let client_verifier =
        WebPkiClientVerifier::builder_with_provider(Arc::new(certs), provider.clone()).build()?;

    let mut server_config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(vec![cert], priv_key)?;
    server_config.max_early_data_size = u32::MAX;
    server_config.alpn_protocols = vec![b"stunnel".to_vec()];

    let server_config = QuicServerConfig::try_from(server_config)?;
    let mut server_config = ServerConfig::with_crypto(Arc::new(server_config));

    let transport = Arc::get_mut(&mut server_config.transport)
        .ok_or_else(|| std::io::Error::other("quinn server transport config is shared"))?;
    transport
        .max_concurrent_bidi_streams(10000u32.into())
        .congestion_controller_factory(cc_factory(config));

    Ok(Endpoint::server(server_config, config.addr)?)
}
