use std::sync::Arc;

use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer, ServerName};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use super::TlsStream;

pub struct Config {
    pub server_addr: String,
    pub server_name: String,
    pub cert: String,
    pub priv_key: String,
}

#[derive(Clone)]
pub struct Connector {
    connector: TlsConnector,
    server_addr: String,
    server_name: String,
}

impl Connector {
    pub async fn connect(&self) -> std::io::Result<TlsStream> {
        let stream = TcpStream::connect(&self.server_addr).await?;
        let domain = ServerName::try_from(self.server_name.as_str())
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::Other, error))?
            .to_owned();
        let stream = self.connector.connect(domain, stream).await?;
        Ok(TlsStream::Client(stream))
    }
}

pub fn new(config: &Config) -> Connector {
    let cert = CertificateDer::from_pem_file(&config.cert).unwrap();
    let priv_key = PrivateKeyDer::from_pem_file(&config.priv_key).unwrap();

    let mut certs = rustls::RootCertStore::empty();
    certs.add(cert.clone()).unwrap();

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let client_config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(certs)
        .with_client_auth_cert(vec![cert], priv_key)
        .unwrap();

    Connector {
        connector: TlsConnector::from(Arc::new(client_config)),
        server_addr: config.server_addr.clone(),
        server_name: config.server_name.clone(),
    }
}
