use std::net::SocketAddr;

use async_h1::server::{decode, Encoder};
use async_std::io;
use async_std::net::TcpStream;
use async_trait::async_trait;
use http_types::{Method, Response, StatusCode};

use crate::proxy::{Destination, Proxy};

pub struct Http;

#[async_trait]
impl Proxy for Http {
    async fn handshake(&mut self, stream: &mut TcpStream) -> std::io::Result<Destination> {
        let http_req = decode(stream.clone()).await;

        match http_req {
            Ok(Some((request, _))) => {
                let method = request.method();
                let url = request.url();
                if method == Method::Connect
                    && url.host_str().is_some()
                    && url.port_or_known_default().is_some()
                {
                    let host = url.host_str().unwrap().to_string();
                    let port = url.port_or_known_default().unwrap();
                    Ok(Destination::DomainName(host.into_bytes(), port))
                } else {
                    Ok(Destination::Unknown)
                }
            }
            _ => Ok(Destination::Unknown),
        }
    }

    async fn destination_unreached(&self, stream: &mut TcpStream) -> std::io::Result<()> {
        let response = Response::new(StatusCode::NotFound);
        let mut encoder = Encoder::new(response, Method::Connect);
        io::copy(&mut encoder, stream).await?;
        Ok(())
    }

    async fn destination_connected(
        &self,
        stream: &mut TcpStream,
        _bind_addr: SocketAddr,
    ) -> std::io::Result<()> {
        let response = Response::new(StatusCode::Ok);
        let mut encoder = Encoder::new(response, Method::Connect);
        io::copy(&mut encoder, stream).await?;
        Ok(())
    }
}
