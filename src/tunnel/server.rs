use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};

use crate::tunnel::Tunnel;

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
