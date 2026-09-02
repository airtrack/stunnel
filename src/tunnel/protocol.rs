//! Wire framing shared by forward, reverse, and control tunnels.

use std::net::SocketAddr;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::Tunnel;

// Tunnel type, the first byte of every tunnel. 0x00-0x01 are client initiated
// (forward), 0x02 is server initiated (reverse), 0x03 is the client initiated
// control tunnel of a connection.
pub(crate) const TYPE_UDP_FWD: u8 = 0x00;
pub(crate) const TYPE_TCP_FWD: u8 = 0x01;
pub(crate) const TYPE_TCP_REV: u8 = 0x02;
pub(crate) const TYPE_CONTROL: u8 = 0x03;

// Control messages, carried on a control tunnel after TYPE_CONTROL.
pub(crate) const CTRL_REGISTER_REVERSE: u8 = 0x01;
// Sent by the client after all registrations: no more control messages
// follow, the server turns the control tunnel into the reverse holder.
pub(crate) const CTRL_REGISTER_REVERSE_END: u8 = 0x02;
pub(crate) const CTRL_ACK: u8 = 0x10;
pub(crate) const CTRL_ERR: u8 = 0x11;

pub(crate) enum ControlReply {
    Ok(String),
    Err(String),
}

impl<S, R> Tunnel<S, R>
where
    S: AsyncWrite + Unpin,
    R: Unpin,
{
    pub(crate) async fn response(&mut self, local_addr: SocketAddr) -> std::io::Result<()> {
        let addr = local_addr.to_string();
        self.write_str8(&addr).await
    }

    pub(crate) async fn write_str8(&mut self, s: &str) -> std::io::Result<()> {
        self.write_u8(s.len() as u8).await?;
        self.write_all(s.as_bytes()).await?;
        Ok(())
    }

    // Registers a reverse proxy on the server: the server binds `listen` and
    // forwards each connection to the client-side `target`.
    pub(crate) async fn send_register_reverse(
        &mut self,
        listen: &str,
        target: &str,
    ) -> std::io::Result<()> {
        self.write_u8(CTRL_REGISTER_REVERSE).await?;
        self.write_str8(listen).await?;
        self.write_str8(target).await?;
        Ok(())
    }

    // Signals the end of reverse proxy registration: no more control messages
    // are sent, the server holds the control tunnel as the reverse holder.
    pub(crate) async fn send_register_reverse_end(&mut self) -> std::io::Result<()> {
        self.write_u8(CTRL_REGISTER_REVERSE_END).await?;
        Ok(())
    }
}

impl<S, R> Tunnel<S, R>
where
    S: Unpin,
    R: AsyncRead + Unpin,
{
    pub(crate) async fn read_str8(&mut self) -> std::io::Result<String> {
        let n = self.read_u8().await? as usize;
        let mut buf = vec![0u8; n];
        self.read_exact(&mut buf)
            .await
            .map_err(std::io::Error::other)?;
        String::from_utf8(buf)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid string"))
    }

    // Reads the server's reply to a control message.
    pub(crate) async fn read_control_reply(&mut self) -> std::io::Result<ControlReply> {
        match self.read_u8().await? {
            CTRL_ACK => Ok(ControlReply::Ok(self.read_str8().await?)),
            CTRL_ERR => Ok(ControlReply::Err(self.read_str8().await?)),
            typ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid control reply type: {typ}"),
            )),
        }
    }
}

#[async_trait]
pub trait AsyncWriteDatagramExt: AsyncWrite {
    async fn send_datagram(&mut self, buf: &[u8], addr: SocketAddr) -> std::io::Result<usize>
    where
        Self: Unpin,
    {
        send_datagram(self, buf, addr).await
    }
}

impl<S: AsyncWrite> AsyncWriteDatagramExt for S {}

#[async_trait]
pub trait AsyncReadDatagramExt: AsyncRead {
    async fn recv_datagram(&mut self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)>
    where
        Self: Unpin,
    {
        recv_datagram(self, buf).await
    }
}

impl<R: AsyncRead> AsyncReadDatagramExt for R {}

async fn send_datagram<T>(writer: &mut T, buf: &[u8], addr: SocketAddr) -> std::io::Result<usize>
where
    T: AsyncWrite + Unpin + ?Sized,
{
    let addr = addr.to_string();
    writer.write_u8(addr.len() as u8).await?;
    writer.write_all(addr.as_bytes()).await?;
    writer.write_u16(buf.len() as u16).await?;
    writer.write_all(buf).await?;
    Ok(buf.len())
}

async fn recv_datagram<T>(reader: &mut T, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)>
where
    T: AsyncRead + Unpin + ?Sized,
{
    let n = reader.read_u8().await? as usize;
    let mut addr = vec![0u8; n];
    reader
        .read_exact(&mut addr)
        .await
        .map_err(std::io::Error::other)?;

    if let Some(addr) = std::str::from_utf8(&addr)
        .ok()
        .and_then(|addr| addr.parse::<SocketAddr>().ok())
    {
        let size = reader.read_u16().await? as usize;
        if size > buf.len() {
            Err(std::io::Error::other("recv buffer overflow"))
        } else {
            reader
                .read_exact(&mut buf[..size])
                .await
                .map_err(std::io::Error::other)?;
            Ok((size, addr))
        }
    } else {
        Err(std::io::Error::other("invalid addr"))
    }
}
