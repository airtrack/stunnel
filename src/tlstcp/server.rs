use std::{error::Error, net::SocketAddr, path::PathBuf, sync::Arc};

use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    server::WebPkiClientVerifier,
};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

use super::TlsStream;

pub struct Config {
    pub addr: SocketAddr,
    pub cert: PathBuf,
    pub priv_key: PathBuf,
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
    new_server(config)
        .await
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::Other, error.to_string()))
}

async fn new_server(config: &Config) -> Result<Acceptor, Box<dyn Error>> {
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
    server_config.alpn_protocols = vec![b"stunnel".to_vec()];

    let listener = TcpListener::bind(config.addr).await?;
    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    Ok(Acceptor { listener, acceptor })
}
