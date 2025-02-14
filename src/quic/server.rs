use std::sync::Arc;

use quinn::{congestion, crypto::rustls::QuicServerConfig, Endpoint, ServerConfig};
use rustls::{
    pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer},
    server::WebPkiClientVerifier,
};

pub struct Config {
    pub addr: String,
    pub cert: String,
    pub priv_key: String,
}

pub fn new(config: &Config) -> std::io::Result<Endpoint> {
    let cert = CertificateDer::from_pem_file(&config.cert).unwrap();
    let priv_key = PrivateKeyDer::from_pem_file(&config.priv_key).unwrap();

    let mut certs = rustls::RootCertStore::empty();
    certs.add(cert.clone()).unwrap();

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let client_verifier =
        WebPkiClientVerifier::builder_with_provider(Arc::new(certs), provider.clone())
            .build()
            .unwrap();

    let mut server_config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(vec![cert], priv_key)
        .unwrap();
    server_config.max_early_data_size = u32::MAX;

    let server_config = QuicServerConfig::try_from(server_config).unwrap();
    let mut server_config = ServerConfig::with_crypto(Arc::new(server_config));

    let transport = Arc::get_mut(&mut server_config.transport).unwrap();
    transport
        .max_concurrent_bidi_streams(10000u32.into())
        .congestion_controller_factory(Arc::new(congestion::BbrConfig::default()));

    let addr = config.addr.parse().unwrap();
    Endpoint::server(server_config, addr)
}
