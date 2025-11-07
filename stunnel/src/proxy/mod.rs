use std::net::SocketAddr;

use async_trait::async_trait;
use tokio::{
    io::{self, AsyncRead, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};

pub mod http;
pub mod socks5;

pub enum ProxyType<T, U> {
    Tcp(T),
    Udp(U),
}

#[async_trait]
pub trait Proxy<T: TcpProxyConn, U: UdpProxyBind> {
    async fn accept(&self, stream: TcpStream) -> std::io::Result<ProxyType<T, U>>;
}

#[async_trait]
pub trait TcpProxyConn {
    fn target_host(&self) -> &str;
    async fn response_connect_ok(&mut self, bind: SocketAddr) -> std::io::Result<()>;
    async fn response_connect_err(&mut self) -> std::io::Result<()>;
    async fn copy_bidirectional<
        R: AsyncRead + Send + Unpin + ?Sized,
        W: AsyncWrite + Send + Unpin + ?Sized,
    >(
        &mut self,
        reader: &mut R,
        writer: &mut W,
    ) -> std::io::Result<(u64, u64)>;
}

#[async_trait]
pub trait UdpProxyBind {
    async fn response_bind_ok(&mut self) -> std::io::Result<()>;
    async fn response_bind_err(&mut self) -> std::io::Result<()>;
    async fn copy_bidirectional(
        self,
        reader: impl AsyncReadDatagram + Send,
        writer: impl AsyncWriteDatagram + Send,
    ) -> std::io::Result<()>;
}

#[async_trait]
pub trait AsyncReadDatagram {
    async fn recv(&mut self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)>;
}

#[async_trait]
pub trait AsyncWriteDatagram {
    async fn send(&mut self, buf: &[u8], addr: SocketAddr) -> std::io::Result<usize>;
}

pub async fn copy_bidirectional<R: AsyncRead + Unpin + ?Sized, W: AsyncWrite + Unpin + ?Sized>(
    stream: &mut TcpStream,
    reader: &mut R,
    writer: &mut W,
) -> std::io::Result<(u64, u64)> {
    let (mut read_half, mut write_half) = stream.split();

    let r = async {
        let result = io::copy(&mut read_half, writer).await;
        writer.shutdown().await.ok();
        result
    };

    let w = async {
        let result = io::copy(reader, &mut write_half).await;
        write_half.shutdown().await.ok();
        result
    };

    futures::try_join!(r, w)
}
