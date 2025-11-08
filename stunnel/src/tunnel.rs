use std::{net::SocketAddr, pin::pin};

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::tlstcp::{self, TlsReadStream, TlsWriteStream};

pub struct Tunnel<S, R> {
    s: S,
    r: R,
}

impl<S, R> Tunnel<S, R> {
    fn new(s: S, r: R) -> Self {
        Self { s, r }
    }

    pub fn split(self) -> (S, R) {
        (self.s, self.r)
    }
}

impl<S, R> Tunnel<S, R>
where
    S: AsyncWrite + Unpin,
    R: Unpin,
{
    pub async fn response(&mut self, local_addr: SocketAddr) -> std::io::Result<()> {
        let addr = local_addr.to_string();
        self.s.write_u8(addr.len() as u8).await?;
        self.s.write_all(addr.as_bytes()).await?;
        Ok(())
    }
}

impl<S, R> AsyncRead for Tunnel<S, R>
where
    S: Unpin,
    R: AsyncRead + Unpin,
{
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        pin!(&mut self.get_mut().r).poll_read(cx, buf)
    }
}

impl<S, R> AsyncWrite for Tunnel<S, R>
where
    S: AsyncWrite + Unpin,
    R: Unpin,
{
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        pin!(&mut self.get_mut().s).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        pin!(&mut self.get_mut().s).poll_write_vectored(cx, bufs)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        pin!(&mut self.get_mut().s).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        pin!(&mut self.get_mut().s).poll_shutdown(cx)
    }

    fn is_write_vectored(&self) -> bool {
        self.s.is_write_vectored()
    }
}

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

#[async_trait]
pub trait AsyncWriteDatagramExt: AsyncWrite {
    async fn send_datagram(&mut self, buf: &[u8], addr: SocketAddr) -> std::io::Result<usize>
    where
        Self: Unpin,
    {
        send_datagram(self, buf, addr).await
    }
}

impl<S: AsyncWrite> AsyncWriteDatagramExt for S {}

#[async_trait]
pub trait AsyncReadDatagramExt: AsyncRead {
    async fn recv_datagram(&mut self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)>
    where
        Self: Unpin,
    {
        recv_datagram(self, buf).await
    }
}

impl<R: AsyncRead> AsyncReadDatagramExt for R {}

async fn recv_datagram<T>(reader: &mut T, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)>
where
    T: AsyncRead + Unpin + ?Sized,
{
    let n = reader.read_u8().await? as usize;
    let mut addr = vec![0u8; n];
    reader
        .read_exact(&mut addr)
        .await
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::Other, error))?;

    if let Some(addr) = std::str::from_utf8(&addr)
        .ok()
        .and_then(|addr| addr.parse::<SocketAddr>().ok())
    {
        let size = reader.read_u16().await? as usize;
        if size > buf.len() {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "recv buffer overflow",
            ))
        } else {
            reader
                .read_exact(&mut buf[..size])
                .await
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::Other, error))?;
            Ok((size, addr))
        }
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "invalid addr",
        ))
    }
}

async fn send_datagram<T>(writer: &mut T, buf: &[u8], addr: SocketAddr) -> std::io::Result<usize>
where
    T: AsyncWrite + Unpin + ?Sized,
{
    let addr = addr.to_string();
    writer.write_u8(addr.len() as u8).await?;
    writer.write_all(addr.as_bytes()).await?;
    writer.write_u16(buf.len() as u16).await?;
    writer.write_all(buf).await?;
    Ok(buf.len())
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

pub enum Incoming<S, R> {
    UdpTunnel(Tunnel<S, R>),
    TcpTunnel((Tunnel<S, R>, String)),
}

pub async fn accept<S, R>(send: S, mut recv: R) -> std::io::Result<Incoming<S, R>>
where
    S: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    let n = recv.read_u8().await? as usize;

    if n == 0 {
        let tun = Tunnel::new(send, recv);
        Ok(Incoming::UdpTunnel(tun))
    } else {
        let mut buf = vec![0u8; n];
        recv.read_exact(&mut buf)
            .await
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::Other, error))?;

        if let Some(addr) = String::from_utf8(buf).ok() {
            let tun = Tunnel::new(send, recv);
            Ok(Incoming::TcpTunnel((tun, addr)))
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid addr",
            ))
        }
    }
}
