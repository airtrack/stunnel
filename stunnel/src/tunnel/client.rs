use std::net::SocketAddr;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::tlstcp::{self, TlsReadStream, TlsWriteStream};
use crate::tunnel::Tunnel;

#[async_trait]
pub trait IntoTunnel<S, R> {
    async fn into_tunnel(self) -> std::io::Result<Tunnel<S, R>>;
}

#[async_trait]
impl IntoTunnel<quinn::SendStream, quinn::RecvStream> for quinn::Connection {
    async fn into_tunnel(self) -> std::io::Result<Tunnel<quinn::SendStream, quinn::RecvStream>> {
        let (send, recv) = self.open_bi().await?;
        Ok(Tunnel { s: send, r: recv })
    }
}

#[async_trait]
impl IntoTunnel<s2n_quic::stream::SendStream, s2n_quic::stream::ReceiveStream>
    for s2n_quic::connection::Handle
{
    async fn into_tunnel(
        mut self,
    ) -> std::io::Result<Tunnel<s2n_quic::stream::SendStream, s2n_quic::stream::ReceiveStream>>
    {
        let stream = self.open_bidirectional_stream().await?;
        let (recv, send) = stream.split();
        Ok(Tunnel { s: send, r: recv })
    }
}

#[async_trait]
impl IntoTunnel<TlsWriteStream, TlsReadStream> for tlstcp::Connector {
    async fn into_tunnel(self) -> std::io::Result<Tunnel<TlsWriteStream, TlsReadStream>> {
        let stream = self.connect().await?;
        let (read_half, write_half) = tlstcp::split(stream);
        Ok(Tunnel {
            s: write_half,
            r: read_half,
        })
    }
}

pub async fn connect_tcp_tunnel<S, R>(
    into: impl IntoTunnel<S, R>,
    target: &str,
) -> std::io::Result<(SocketAddr, Tunnel<S, R>)>
where
    S: AsyncWrite + Send + Unpin,
    R: AsyncRead + Send + Unpin,
{
    let mut conn = into.into_tunnel().await?;

    conn.write_u8(target.len() as u8).await?;
    conn.write_all(target.as_bytes()).await?;

    let n = conn.read_u8().await? as usize;
    let mut buf = vec![0u8; n];
    conn.read_exact(&mut buf)
        .await
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::Other, error))?;

    if let Some(bind) = std::str::from_utf8(&buf)
        .ok()
        .and_then(|addr| addr.parse::<SocketAddr>().ok())
    {
        Ok((bind, conn))
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid addr",
        ))
    }
}

pub async fn connect_udp_tunnel<S, R>(into: impl IntoTunnel<S, R>) -> std::io::Result<Tunnel<S, R>>
where
    S: AsyncWrite + Send + Unpin,
    R: AsyncRead + Send + Unpin,
{
    let mut conn = into.into_tunnel().await?;

    conn.write_u8(0).await?;

    let n = conn.read_u8().await? as usize;
    let mut buf = vec![0u8; n];
    conn.read_exact(&mut buf)
        .await
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::Other, error))?;

    Ok(conn)
}
