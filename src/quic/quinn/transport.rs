use async_trait::async_trait;

use crate::tunnel::{AcceptTunnel, OpenTunnel, Tunnel};

#[async_trait]
impl OpenTunnel for quinn::Connection {
    type S = quinn::SendStream;
    type R = quinn::RecvStream;

    async fn open_tunnel(&mut self) -> std::io::Result<Tunnel<Self::S, Self::R>> {
        let (send, recv) = self.open_bi().await.map_err(std::io::Error::other)?;
        Ok(Tunnel::new(send, recv))
    }
}

#[async_trait]
impl AcceptTunnel for quinn::Connection {
    type S = quinn::SendStream;
    type R = quinn::RecvStream;

    async fn accept_tunnel(&mut self) -> std::io::Result<Tunnel<Self::S, Self::R>> {
        let (send, recv) = self.accept_bi().await?;
        Ok(Tunnel::new(send, recv))
    }
}
