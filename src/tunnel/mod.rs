use std::pin::Pin;

use tokio::io::{AsyncRead, AsyncWrite};

pub mod client;
pub mod server;

mod protocol;
mod transport;

pub use protocol::{AsyncReadDatagramExt, AsyncWriteDatagramExt};
pub(crate) use protocol::{
    CTRL_ACK, CTRL_ERR, CTRL_REGISTER_REVERSE, CTRL_REGISTER_REVERSE_END, ControlReply,
    TYPE_CONTROL, TYPE_TCP_FWD, TYPE_TCP_REV, TYPE_UDP_FWD,
};
pub use transport::{AcceptTunnel, OpenTunnel};

pub struct Tunnel<S, R> {
    s: S,
    r: R,
}

impl<S, R> Tunnel<S, R> {
    pub(crate) fn new(s: S, r: R) -> Self {
        Self { s, r }
    }

    pub fn split(self) -> (S, R) {
        (self.s, self.r)
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
