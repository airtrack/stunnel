use std::{sync::Arc, time::Duration};

use quinn::{
    congestion, crypto::rustls::QuicClientConfig, ClientConfig, Endpoint, TransportConfig,
};
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};

use crate::quic::Config;

pub fn new(config: &Config) -> std::io::Result<Endpoint> {
    let cert = CertificateDer::from_pem_file(&config.cert).unwrap();
    let priv_key = PrivateKeyDer::from_pem_file(&config.priv_key).unwrap();

    let mut certs = rustls::RootCertStore::empty();
    certs.add(cert.clone()).unwrap();

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut client_config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(certs)
        .with_client_auth_cert(vec![cert], priv_key)
        .unwrap();
    client_config.enable_early_data = true;
    client_config.alpn_protocols = vec![b"stunnel".to_vec()];

    let client_config = QuicClientConfig::try_from(client_config).unwrap();
    let mut client_config = ClientConfig::new(Arc::new(client_config));

    let mut transport = TransportConfig::default();
    transport
        .max_concurrent_bidi_streams(10000u32.into())
        .keep_alive_interval(Some(Duration::from_secs(3)))
        .congestion_controller_factory(Arc::new(congestion::BbrConfig::default()));

    client_config.transport_config(Arc::new(transport));

    let addr = config.addr.parse().unwrap();
    let mut endpoint = Endpoint::client(addr)?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}
