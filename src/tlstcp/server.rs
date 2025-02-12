use std::sync::Arc;

use rustls::{
    pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer},
    server::WebPkiClientVerifier,
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

pub async fn new(config: &Config) -> Acceptor {
    let cert = CertificateDer::from_pem_file(&config.cert).unwrap();
    let priv_key = PrivateKeyDer::from_pem_file(&config.priv_key).unwrap();

    let mut certs = rustls::RootCertStore::empty();
    certs.add(cert.clone()).unwrap();

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let client_verifier =
        WebPkiClientVerifier::builder_with_provider(Arc::new(certs), provider.clone())
            .build()
            .unwrap();

    let server_config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(vec![cert], priv_key)
        .unwrap();

    let listener = TcpListener::bind(&config.addr).await.unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    Acceptor { listener, acceptor }
}
