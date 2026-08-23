use async_trait::async_trait;

use crate::tunnel::{OpenTunnel, Tunnel};

use super::{Connector, TlsReadStream, TlsWriteStream, split};

#[async_trait]
impl OpenTunnel for Connector {
    type S = TlsWriteStream;
    type R = TlsReadStream;

    async fn open_tunnel(&mut self) -> std::io::Result<Tunnel<Self::S, Self::R>> {
        let stream = self.connect().await?;
        let (read_half, write_half) = split(stream);
        Ok(Tunnel::new(write_half, read_half))
    }
}
