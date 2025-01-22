use tokio::{
    io::{self, AsyncRead, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};

pub mod http;
pub mod socks5;

pub async fn copy_bidirectional<R, W>(
    stream: &mut TcpStream,
    reader: &mut R,
    writer: &mut W,
) -> std::io::Result<(u64, u64)>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
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
