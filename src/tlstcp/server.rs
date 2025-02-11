use std::sync::Arc;

use rustls::pki_types::{
    pem::{self, PemObject},
    CertificateDer, PrivateKeyDer,
};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

use super::TlsStream;

pub struct Config {
    pub addr: String,
    pub cert: String,
    pub priv_key: String,
}

pub struct Acceptor {
    listener: TcpListener,
    acceptor: TlsAcceptor,
}

impl Acceptor {
    pub async fn accept(&self) -> std::io::Result<Accepting> {
        let (stream, _) = self.listener.accept().await?;
        let acceptor = self.acceptor.clone();
        Ok(Accepting { stream, acceptor })
    }
}

pub struct Accepting {
    stream: TcpStream,
    acceptor: TlsAcceptor,
}

impl Accepting {
    pub async fn accept(self) -> std::io::Result<TlsStream> {
        let stream = self.acceptor.accept(self.stream).await?;
        Ok(TlsStream::Server(stream))
    }
}

pub async fn new(config: &Config) -> std::io::Result<Acceptor> {
    let cert = CertificateDer::from_pem_file(&config.cert).map_err(|error| match error {
        pem::Error::Io(e) => return e,
        _ => return std::io::Error::new(std::io::ErrorKind::Other, error),
    })?;

    let priv_key = PrivateKeyDer::from_pem_file(&config.priv_key).map_err(|error| match error {
        pem::Error::Io(e) => return e,
        _ => return std::io::Error::new(std::io::ErrorKind::Other, error),
    })?;

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let server_config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], priv_key)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::Other, error))?;

    let listener = TcpListener::bind(&config.addr).await?;
    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    Ok(Acceptor { listener, acceptor })
}
