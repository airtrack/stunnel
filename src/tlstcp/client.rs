use std::{error::Error, net::SocketAddr, path::PathBuf, sync::Arc};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use super::TlsStream;

pub struct Config {
    pub server_addr: SocketAddr,
    pub server_name: String,
    pub cert: PathBuf,
    pub priv_key: PathBuf,
}

#[derive(Clone)]
pub struct Connector {
    connector: TlsConnector,
    server_addr: SocketAddr,
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

pub fn new(config: &Config) -> std::io::Result<Connector> {
    new_client(config)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::Other, error.to_string()))
}

fn new_client(config: &Config) -> Result<Connector, Box<dyn Error>> {
    let cert = CertificateDer::from_pem_file(&config.cert)?;
    let priv_key = PrivateKeyDer::from_pem_file(&config.priv_key)?;

    let mut certs = rustls::RootCertStore::empty();
    certs.add(cert.clone())?;

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut client_config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(certs)
        .with_client_auth_cert(vec![cert], priv_key)?;
    client_config.alpn_protocols = vec![b"stunnel".to_vec()];

    Ok(Connector {
        connector: TlsConnector::from(Arc::new(client_config)),
        server_addr: config.server_addr,
        server_name: config.server_name.clone(),
    })
}
