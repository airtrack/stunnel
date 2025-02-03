use std::net::SocketAddr;

use async_trait::async_trait;
use tokio::{
    io::{self, AsyncRead, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};

pub mod http;
pub mod socks5;

#[async_trait]
pub trait TcpProxyConn {
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
