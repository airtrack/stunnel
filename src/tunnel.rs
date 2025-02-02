use std::net::SocketAddr;

use async_trait::async_trait;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};

use crate::proxy::{copy_bidirectional, socks5::Socks5TcpStream};

pub struct TunnelConn<S: AsyncWrite + Send + Unpin, R: AsyncRead + Send + Unpin> {
    s: S,
    r: R,
}

impl<S: AsyncWrite + Send + Unpin, R: AsyncRead + Send + Unpin> TunnelConn<S, R> {
    fn split(
        &mut self,
    ) -> (
        &mut (dyn AsyncWrite + Send + Unpin),
        &mut (dyn AsyncRead + Send + Unpin),
    ) {
        (&mut self.s, &mut self.r)
    }
}

#[async_trait]
pub trait IntoTunnel<S: AsyncWrite + Send + Unpin, R: AsyncRead + Send + Unpin> {
    async fn into_tcp_tunnel(self) -> std::io::Result<TunnelConn<S, R>>;
}

#[async_trait]
impl IntoTunnel<quinn::SendStream, quinn::RecvStream> for quinn::Connection {
    async fn into_tcp_tunnel(
        self,
    ) -> std::io::Result<TunnelConn<quinn::SendStream, quinn::RecvStream>> {
        let (send, recv) = self.open_bi().await?;
        Ok(TunnelConn { s: send, r: recv })
    }
}

pub async fn handle_socks5_tcp<S: AsyncWrite + Send + Unpin, R: AsyncRead + Send + Unpin>(
    into: impl IntoTunnel<S, R>,
    host: &str,
    stream: &mut Socks5TcpStream,
) -> std::io::Result<(u64, u64)> {
    match handle_socks5_tcp_tunnel(into, host, stream).await {
        Ok(r) => Ok(r),
        Err(e) => {
            stream.connect_err().await.ok();
            Err(e)
        }
    }
}

async fn handle_socks5_tcp_tunnel<S: AsyncWrite + Send + Unpin, R: AsyncRead + Send + Unpin>(
    into: impl IntoTunnel<S, R>,
    host: &str,
    stream: &mut Socks5TcpStream,
) -> std::io::Result<(u64, u64)> {
    let mut conn = into.into_tcp_tunnel().await?;
    let (writer, reader) = conn.split();

    writer.write_u8(host.len() as u8).await?;
    writer.write_all(host.as_bytes()).await?;

    let n = reader.read_u8().await? as usize;
    let mut buf = vec![0u8; n];
    reader
        .read_exact(&mut buf)
        .await
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::Other, error))?;

    if let Some(bind) = std::str::from_utf8(&buf)
        .ok()
        .and_then(|addr| addr.parse::<SocketAddr>().ok())
    {
        stream.connect_ok(bind).await?;
        stream.copy_bidirectional(reader, writer).await
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid addr",
        ))
    }
}

pub async fn handle_tcp_tunnel<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    writer: &mut W,
    reader: &mut R,
) -> std::io::Result<(u64, u64)> {
    let n = reader.read_u8().await? as usize;
    let mut buf = vec![0u8; n];
    reader
        .read_exact(&mut buf)
        .await
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::Other, error))?;

    if let Some(addr) = std::str::from_utf8(&buf).ok() {
        let mut stream = TcpStream::connect(addr).await?;
        let addr = stream.local_addr()?.to_string();
        writer.write_u8(addr.len() as u8).await?;
        writer.write_all(addr.as_bytes()).await?;
        copy_bidirectional(&mut stream, reader, writer).await
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid addr",
        ))
    }
}
