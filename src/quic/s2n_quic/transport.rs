use async_trait::async_trait;

use crate::tunnel::{AcceptTunnel, OpenTunnel, Tunnel};

#[async_trait]
impl OpenTunnel for s2n_quic::connection::Handle {
    type S = s2n_quic::stream::SendStream;
    type R = s2n_quic::stream::ReceiveStream;

    async fn open_tunnel(&mut self) -> std::io::Result<Tunnel<Self::S, Self::R>> {
        let stream = self
            .open_bidirectional_stream()
            .await
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::Other, error))?;
        let (recv, send) = stream.split();
        Ok(Tunnel::new(send, recv))
    }
}

#[async_trait]
impl AcceptTunnel for s2n_quic::connection::StreamAcceptor {
    type S = s2n_quic::stream::SendStream;
    type R = s2n_quic::stream::ReceiveStream;

    async fn accept_tunnel(&mut self) -> std::io::Result<Tunnel<Self::S, Self::R>> {
        let stream = self
            .accept_bidirectional_stream()
            .await?
            .ok_or(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "conn closed",
            ))?;
        let (recv, send) = stream.split();
        Ok(Tunnel::new(send, recv))
    }
}
