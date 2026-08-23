use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite};

use super::Tunnel;

// Opens a tunnel on the transport connection: opens a stream and wraps it in
// a Tunnel. Used by the client for forward and control tunnels and by the
// server to send reverse tunnels back to the client.
#[async_trait]
pub trait OpenTunnel: Clone + Send + 'static {
    type S: AsyncWrite + Send + Unpin;
    type R: AsyncRead + Send + Unpin;

    async fn open_tunnel(&mut self) -> std::io::Result<Tunnel<Self::S, Self::R>>;
}

// Accepts the next tunnel of a connection: accepts a stream and wraps it in
// a Tunnel, or errors when the connection is closed.
#[async_trait]
pub trait AcceptTunnel: Send + 'static {
    type S: AsyncWrite + Send + Unpin;
    type R: AsyncRead + Send + Unpin;

    async fn accept_tunnel(&mut self) -> std::io::Result<Tunnel<Self::S, Self::R>>;
}
