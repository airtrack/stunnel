use std::{net::SocketAddr, pin::pin};

use async_trait::async_trait;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::UdpSocket,
};

use crate::{
    proxy::{AsyncReadDatagram, AsyncWriteDatagram, TcpProxyConn, UdpProxyBind},
    tlstcp::{self, TlsReadStream, TlsWriteStream},
};

pub struct Tunnel<S, R> {
    s: S,
    r: R,
}

impl<S, R> Tunnel<S, R> {
    fn new(s: S, r: R) -> Self {
        Self { s, r }
    }

    fn split(self) -> (S, R) {
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
impl AsyncReadDatagram for s2n_quic::stream::ReceiveStream {
    async fn recv(&mut self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        recv_datagram(self, buf).await
    }
}

#[async_trait]
impl AsyncWriteDatagram for s2n_quic::stream::SendStream {
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

pub async fn copy_bidirectional_udp_socket<S, R>(
    tun: Tunnel<S, R>,
    socket: &UdpSocket,
) -> std::io::Result<(u64, u64)>
where
    S: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    async fn r<S>(socket: &UdpSocket, send: &mut S) -> std::io::Result<()>
    where
        S: AsyncWrite + Unpin,
    {
        let mut buf = [0u8; 1500];
        loop {
            let (n, from) = socket.recv_from(&mut buf).await?;
            send_datagram(send, &buf[..n], from).await?;
        }
    }

    async fn w<R>(socket: &UdpSocket, recv: &mut R) -> std::io::Result<()>
    where
        R: AsyncRead + Unpin,
    {
        let mut buf = [0u8; 1500];
        loop {
            let (n, target) = recv_datagram(recv, &mut buf).await?;
            socket.send_to(&buf[..n], target).await?;
        }
    }

    let (mut send, mut recv) = tun.split();
    futures::try_join!(r(socket, &mut send), w(socket, &mut recv)).map(|_| (0, 0))
}

async fn recv_datagram<T>(reader: &mut T, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)>
where
    T: AsyncRead + Unpin,
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
    T: AsyncWrite + Unpin,
{
    let addr = addr.to_string();
    writer.write_u8(addr.len() as u8).await?;
    writer.write_all(addr.as_bytes()).await?;
    writer.write_u16(buf.len() as u16).await?;
    writer.write_all(buf).await?;
    Ok(buf.len())
}

pub async fn start_tcp_tunnel<S, R, T>(
    into: impl IntoTunnel<S, R>,
    target: &str,
    tcp: &mut T,
) -> std::io::Result<(u64, u64)>
where
    S: AsyncWrite + Send + Unpin,
    R: AsyncRead + Send + Unpin,
    T: TcpProxyConn,
{
    match connect_tcp_tunnel(into, target).await {
        Ok((bind, conn)) => {
            tcp.response_connect_ok(bind).await?;
            let (mut writer, mut reader) = conn.split();
            tcp.copy_bidirectional(&mut reader, &mut writer).await
        }
        Err(e) => {
            tcp.response_connect_err().await.ok();
            Err(e)
        }
    }
}

async fn connect_tcp_tunnel<S, R>(
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

pub async fn start_udp_tunnel<S, R, U>(
    into: impl IntoTunnel<S, R>,
    mut udp: U,
) -> std::io::Result<()>
where
    S: AsyncWriteDatagram + AsyncWrite + Send + Unpin,
    R: AsyncReadDatagram + AsyncRead + Send + Unpin,
    U: UdpProxyBind,
{
    match connect_udp_tunnel(into).await {
        Ok(conn) => {
            udp.response_bind_ok().await?;
            let (writer, reader) = conn.split();
            udp.copy_bidirectional(reader, writer).await
        }
        Err(error) => {
            udp.response_bind_err().await.ok();
            Err(error)
        }
    }
}

async fn connect_udp_tunnel<S, R>(into: impl IntoTunnel<S, R>) -> std::io::Result<Tunnel<S, R>>
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
