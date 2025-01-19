use std::io::{Error, ErrorKind};

use httparse::Status;
use log::info;
use tokio::{
    io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

pub struct HttpProxy {
    stream: TcpStream,
    host: String,
    request: Option<Vec<u8>>,
}

impl HttpProxy {
    pub async fn accept(mut stream: TcpStream) -> std::io::Result<Self> {
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
                    return Ok(Self {
                        stream,
                        host,
                        request: None,
                    });
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
                return Ok(Self {
                    stream,
                    host,
                    request: Some(buf),
                });
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
                    info!("parse HTTP response partial, len: {}", len);
                    continue;
                }
                Err(_) => {
                    return Err(Error::new(ErrorKind::Other, "connect proxy error"));
                }
            }
        }

        Err(Error::new(ErrorKind::Other, "proxy response too large"))
    }

    pub async fn copy_bidirectional_tcp_stream(
        &mut self,
        other: &mut TcpStream,
    ) -> std::io::Result<(u64, u64)> {
        if let Some(ref request) = self.request {
            other.write_all(request).await?;
        } else {
            self.response_200().await?;
        }

        copy_bidirectional(&mut self.stream, other).await
    }

    pub fn host(&self) -> &String {
        &self.host
    }

    async fn response_200(&mut self) -> std::io::Result<()> {
        const HTTP_200_OK: &str = "HTTP/1.1 200 OK\r\n\r\n";
        self.stream.write_all(HTTP_200_OK.as_bytes()).await
    }
}
