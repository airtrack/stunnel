use std::{net::SocketAddr, pin::Pin};

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub mod client;
pub mod server;

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
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.r).poll_read(cx, buf)
    }
}

impl<S, R> AsyncWrite for Tunnel<S, R>
where
    S: AsyncWrite + Unpin,
    R: Unpin,
{
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.s).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.s).poll_write_vectored(cx, bufs)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.s).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.s).poll_shutdown(cx)
    }

    fn is_write_vectored(&self) -> bool {
        self.s.is_write_vectored()
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
