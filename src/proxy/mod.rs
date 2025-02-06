use std::{net::SocketAddr, sync::Arc};

use async_trait::async_trait;
use tokio::{
    io::{self, AsyncRead, AsyncWrite, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
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
    async fn copy_bidirectional(self, other: impl DatagramRw + Send) -> std::io::Result<()>;
}

#[async_trait]
pub trait DatagramRw: Clone {
    async fn send(&self, buf: &[u8], target: SocketAddr) -> std::io::Result<usize>;
    async fn recv(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)>;
}

#[async_trait]
impl DatagramRw for Arc<UdpSocket> {
    async fn send(&self, buf: &[u8], target: SocketAddr) -> std::io::Result<usize> {
        self.send_to(buf, target).await
    }

    async fn recv(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        self.recv_from(buf).await
    }
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
