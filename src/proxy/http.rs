use std::{
    io::{Error, ErrorKind},
    net::SocketAddr,
};

use async_trait::async_trait;
use httparse::Status;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};

use super::{DatagramRw, Proxy, ProxyType, TcpProxyConn, UdpProxyBind};

#[derive(Clone, Copy)]
pub struct HttpProxy;

#[async_trait]
impl Proxy<HttpTcpProxy, HttpNoUdp> for HttpProxy {
    async fn accept(
        &self,
        stream: TcpStream,
    ) -> std::io::Result<ProxyType<HttpTcpProxy, HttpNoUdp>> {
        Self::accept(stream).await
    }
}

impl HttpProxy {
    pub async fn accept(
        mut stream: TcpStream,
    ) -> std::io::Result<ProxyType<HttpTcpProxy, HttpNoUdp>> {
        let mut buf = vec![0u8; 1500];
        let mut len = 0;

        while len < buf.len() {
            let size = stream.read(&mut buf[len..]).await?;
            if size == 0 {
                return Err(Error::new(ErrorKind::ConnectionAborted, "client closed"));
            }
            len += size;

            let mut headers = [httparse::EMPTY_HEADER; 16];
            let mut req = httparse::Request::new(&mut headers);

            match req.parse(&buf[0..len]) {
                Ok(Status::Complete(_)) => {}
                Ok(Status::Partial) => {
                    continue;
                }
                Err(_) => {
                    return Err(Error::new(ErrorKind::Other, "http error"));
                }
            }

            let is_connect_method = |m: &str| m.to_ascii_uppercase() == "CONNECT";

            if req.method.map_or_else(|| false, is_connect_method) {
                if req.path.is_none() {
                    return Err(Error::new(ErrorKind::Other, "CONNECT path empty"));
                } else {
                    let host = req.path.unwrap().to_string();
                    return Ok(ProxyType::Tcp(HttpTcpProxy::new(stream, host, None)));
                }
            } else {
                let mut host: String = String::default();
                for header in req.headers {
                    if header.name.to_ascii_uppercase() == "HOST" {
                        host = String::from_utf8(header.value.to_vec()).unwrap_or_default();
                        break;
                    }
                }

                if host.is_empty() {
                    return Err(Error::new(ErrorKind::Other, "Host empty"));
                }

                if !host.contains(':') {
                    host.push_str(":80");
                }

                buf.truncate(len);
                return Ok(ProxyType::Tcp(HttpTcpProxy::new(stream, host, Some(buf))));
            }
        }

        Err(Error::new(ErrorKind::Other, "http header too large"))
    }

    pub async fn connect(addr: &String, host: &String) -> std::io::Result<TcpStream> {
        let mut proxy = TcpStream::connect(addr).await?;
        let req = format!("CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n", host, host);
        proxy.write_all(req.as_bytes()).await?;

        let mut buf = [0u8; 1500];
        let mut len = 0;

        while len < buf.len() {
            let size = proxy.read(&mut buf[len..]).await?;
            if size == 0 {
                return Err(Error::new(ErrorKind::ConnectionReset, "proxy closed"));
            }
            len += size;

            let mut headers = [httparse::EMPTY_HEADER; 16];
            let mut resp = httparse::Response::new(&mut headers);

            match resp.parse(&buf[0..len]) {
                Ok(Status::Complete(offset)) => {
                    let code = resp.code.unwrap_or_default();
                    if code >= 200 && code < 300 && len == offset {
                        return Ok(proxy);
                    }

                    let error = format!("proxy response code {}", code);
                    return Err(Error::new(ErrorKind::Other, error));
                }
                Ok(Status::Partial) => {
                    continue;
                }
                Err(_) => {
                    return Err(Error::new(ErrorKind::Other, "connect proxy error"));
                }
            }
        }

        Err(Error::new(ErrorKind::Other, "proxy response too large"))
    }
}

pub struct HttpTcpProxy {
    stream: TcpStream,
    host: String,
    request: Option<Vec<u8>>,
}

impl HttpTcpProxy {
    fn new(stream: TcpStream, host: String, request: Option<Vec<u8>>) -> Self {
        Self {
            stream,
            host,
            request,
        }
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub async fn response_200(&mut self) -> std::io::Result<()> {
        if self.request.is_some() {
            Ok(())
        } else {
            const HTTP_200_OK: &str = "HTTP/1.1 200 OK\r\n\r\n";
            self.stream.write_all(HTTP_200_OK.as_bytes()).await
        }
    }

    pub async fn copy_bidirectional<
        R: AsyncRead + Unpin + ?Sized,
        W: AsyncWrite + Unpin + ?Sized,
    >(
        &mut self,
        reader: &mut R,
        writer: &mut W,
    ) -> std::io::Result<(u64, u64)> {
        if let Some(ref request) = self.request {
            writer.write_all(request).await?;
        }
        super::copy_bidirectional(&mut self.stream, reader, writer).await
    }
}

#[async_trait]
impl TcpProxyConn for HttpTcpProxy {
    fn target_host(&self) -> &str {
        self.host()
    }

    async fn response_connect_ok(&mut self, _bind: SocketAddr) -> std::io::Result<()> {
        self.response_200().await
    }

    async fn response_connect_err(&mut self) -> std::io::Result<()> {
        Ok(())
    }

    async fn copy_bidirectional<
        R: AsyncRead + Send + Unpin + ?Sized,
        W: AsyncWrite + Send + Unpin + ?Sized,
    >(
        &mut self,
        reader: &mut R,
        writer: &mut W,
    ) -> std::io::Result<(u64, u64)> {
        self.copy_bidirectional(reader, writer).await
    }
}

pub struct HttpNoUdp;

#[async_trait]
impl UdpProxyBind for HttpNoUdp {
    async fn response_bind_ok(&mut self) -> std::io::Result<()> {
        panic!("not supported")
    }

    async fn response_bind_err(&mut self) -> std::io::Result<()> {
        panic!("not supported")
    }

    async fn copy_bidirectional(self, _other: impl DatagramRw + Send) -> std::io::Result<()> {
        panic!("not supported")
    }
}
