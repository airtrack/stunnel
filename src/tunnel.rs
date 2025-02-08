use std::net::SocketAddr;

use async_trait::async_trait;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
};

use crate::{
    proxy::{
        copy_bidirectional, copy_bidirectional_udp_socket, AsyncReadDatagram, AsyncWriteDatagram,
        TcpProxyConn, UdpProxyBind,
    },
    tlstcp::{self, TlsReadStream, TlsWriteStream},
};

pub struct Tunnel<S, R> {
    s: S,
    r: R,
}

impl<S, R> Tunnel<S, R> {
    fn into_split(self) -> (S, R) {
        (self.s, self.r)
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
impl AsyncReadDatagram for quinn::RecvStream {
    async fn recv(&mut self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        recv_datagram(self, buf).await
    }
}

#[async_trait]
impl AsyncWriteDatagram for quinn::SendStream {
    async fn send(&mut self, buf: &[u8], addr: SocketAddr) -> std::io::Result<usize> {
        send_datagram(self, buf, addr).await
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
impl AsyncReadDatagram for tlstcp::TlsReadStream {
    async fn recv(&mut self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        recv_datagram(self, buf).await
    }
}

#[async_trait]
impl AsyncWriteDatagram for tlstcp::TlsWriteStream {
    async fn send(&mut self, buf: &[u8], addr: SocketAddr) -> std::io::Result<usize> {
        send_datagram(self, buf, addr).await
    }
}

async fn recv_datagram<T: AsyncRead + Unpin>(
    reader: &mut T,
    buf: &mut [u8],
) -> std::io::Result<(usize, SocketAddr)> {
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

async fn send_datagram<T: AsyncWrite + Unpin>(
    writer: &mut T,
    buf: &[u8],
    addr: SocketAddr,
) -> std::io::Result<usize> {
    let addr = addr.to_string();
    writer.write_u8(addr.len() as u8).await?;
    writer.write_all(addr.as_bytes()).await?;
    writer.write_u16(buf.len() as u16).await?;
    writer.write_all(buf).await?;
    Ok(buf.len())
}

pub async fn start_tcp_tunnel<
    S: AsyncWrite + Send + Unpin,
    R: AsyncRead + Send + Unpin,
    T: TcpProxyConn,
>(
    into: impl IntoTunnel<S, R>,
    target: &str,
    tcp: &mut T,
) -> std::io::Result<(u64, u64)> {
    match connect_tcp_tunnel(into, target).await {
        Ok((bind, mut writer, mut reader)) => {
            tcp.response_connect_ok(bind).await?;
            tcp.copy_bidirectional(&mut reader, &mut writer).await
        }
        Err(e) => {
            tcp.response_connect_err().await.ok();
            Err(e)
        }
    }
}

async fn connect_tcp_tunnel<S: AsyncWrite + Send + Unpin, R: AsyncRead + Send + Unpin>(
    into: impl IntoTunnel<S, R>,
    target: &str,
) -> std::io::Result<(SocketAddr, S, R)> {
    let conn = into.into_tunnel().await?;
    let (mut writer, mut reader) = conn.into_split();

    writer.write_u8(target.len() as u8).await?;
    writer.write_all(target.as_bytes()).await?;

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
        Ok((bind, writer, reader))
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid addr",
        ))
    }
}

pub async fn start_udp_tunnel<
    S: AsyncWriteDatagram + AsyncWrite + Send + Unpin,
    R: AsyncReadDatagram + AsyncRead + Send + Unpin,
    U: UdpProxyBind,
>(
    into: impl IntoTunnel<S, R>,
    mut udp: U,
) -> std::io::Result<()> {
    match connect_udp_tunnel(into).await {
        Ok((writer, reader)) => {
            udp.response_bind_ok().await?;
            udp.copy_bidirectional(reader, writer).await
        }
        Err(error) => {
            udp.response_bind_err().await.ok();
            Err(error)
        }
    }
}

async fn connect_udp_tunnel<
    S: AsyncWriteDatagram + AsyncWrite + Send + Unpin,
    R: AsyncReadDatagram + AsyncRead + Send + Unpin,
>(
    into: impl IntoTunnel<S, R>,
) -> std::io::Result<(S, R)> {
    let conn = into.into_tunnel().await?;
    let (mut writer, mut reader) = conn.into_split();

    writer.write_u8(0).await?;

    let n = reader.read_u8().await? as usize;
    let mut buf = vec![0u8; n];
    reader
        .read_exact(&mut buf)
        .await
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::Other, error))?;

    Ok((writer, reader))
}

pub async fn handle_tunnel<
    R: AsyncReadDatagram + AsyncRead + Unpin,
    W: AsyncWriteDatagram + AsyncWrite + Unpin,
>(
    writer: &mut W,
    reader: &mut R,
) -> std::io::Result<(u64, u64)> {
    let n = reader.read_u8().await? as usize;

    if n == 0 {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let addr = socket.local_addr()?.to_string();
        writer.write_u8(addr.len() as u8).await?;
        writer.write_all(addr.as_bytes()).await?;
        copy_bidirectional_udp_socket(&socket, reader, writer).await
    } else {
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
}
