use std::io::{Cursor, Error, ErrorKind, Result};
use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::proto::*;

pub struct UdpSocketBuf {
    buf: [u8; 1500],
    header_start: usize,
    header_len: usize,
    data_len: usize,
}

impl UdpSocketBuf {
    pub fn new() -> Self {
        Self {
            buf: [0; _],
            header_start: 0,
            header_len: 0,
            data_len: 0,
        }
    }

    pub fn as_mut(&mut self) -> &mut [u8] {
        &mut self.buf[22..]
    }

    pub fn set_len(&mut self, len: usize) {
        self.data_len = len;
    }

    pub fn as_ref(&self) -> &[u8] {
        &self.buf[self.header_start + self.header_len
            ..self.header_start + self.header_len + self.data_len]
    }

    fn set_header_info(&mut self, start: usize, len: usize) {
        self.header_start = start;
        self.header_len = len;
    }

    fn packet_slice(&self) -> &[u8] {
        &self.buf[self.header_start..self.header_start + self.header_len + self.data_len]
    }
}

pub struct UdpSocket {
    inner: UdpSocketInner,
    peer_addr: SocketAddr,
}

impl UdpSocket {
    pub(crate) fn from(inner: UdpSocketInner, peer_addr: SocketAddr) -> Self {
        Self { inner, peer_addr }
    }

    #[inline]
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    #[inline]
    pub async fn send(&self, buf: &mut UdpSocketBuf, addr: SocketAddr) -> Result<()> {
        self.inner.send(buf, addr, self.peer_addr).await
    }

    #[inline]
    pub async fn recv(&self, buf: &mut UdpSocketBuf) -> Result<SocketAddr> {
        let (_, addr) = self.inner.recv(buf).await?;
        Ok(addr)
    }
}

pub(crate) struct UdpSocketInner {
    socket: tokio::net::UdpSocket,
}

impl UdpSocketInner {
    pub(crate) fn from(socket: tokio::net::UdpSocket) -> Self {
        Self { socket }
    }

    pub(crate) async fn send(
        &self,
        buf: &mut UdpSocketBuf,
        addr: SocketAddr,
        peer_addr: SocketAddr,
    ) -> Result<()> {
        let (header_start, header_len) = match addr {
            SocketAddr::V4(_) => (12, 10),
            SocketAddr::V6(_) => (0, 22),
        };

        let header_slice = &mut buf.buf[header_start..header_start + header_len];
        let mut cursor = Cursor::new(header_slice);

        cursor.write_u8(0).await?;
        cursor.write_u8(0).await?;
        cursor.write_u8(0).await?;

        let address = Address::Ip(addr);
        address.write(&mut cursor).await?;

        buf.set_header_info(header_start, header_len);
        self.socket.send_to(buf.packet_slice(), peer_addr).await?;
        Ok(())
    }

    pub(crate) async fn recv(&self, buf: &mut UdpSocketBuf) -> Result<(SocketAddr, SocketAddr)> {
        loop {
            let (n, from) = self.socket.recv_from(&mut buf.buf).await?;
            let mut cursor = Cursor::new(&buf.buf[..n]);

            cursor.set_position(3);

            let address = Address::read(&mut cursor).await?;
            let header_len = cursor.position() as usize;

            match address {
                Address::Ip(addr) => {
                    buf.set_header_info(0, header_len);
                    buf.set_len(n - header_len);
                    return Ok((from, addr));
                }
                Address::Host(_) => {
                    continue;
                }
            }
        }
    }
}

pub struct UdpSocketHolder {
    stream: TcpStream,
}

impl UdpSocketHolder {
    pub(crate) fn new(stream: TcpStream) -> UdpSocketHolder {
        Self { stream }
    }

    pub async fn wait(&mut self) -> Result<()> {
        loop {
            let mut buffer = [0u8; 1024];
            let size = self.stream.read(&mut buffer).await?;
            if size == 0 {
                return Err(Error::new(
                    ErrorKind::ConnectionAborted,
                    "socks5: holding tcp conn of udp was closed",
                ));
            }
        }
    }
}
