use std::io::{Error, ErrorKind, Result};
use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, ToSocketAddrs};

use crate::proto::*;
use crate::udp::*;

pub async fn connect<A: ToSocketAddrs>(socks5: A, destination: Address) -> Result<TcpStream> {
    let mut connector = Connector::new(socks5).await?;
    connector.handshake(destination, CMD_CONNECT).await?;
    Ok(connector.stream)
}

pub async fn udp_associate<A: ToSocketAddrs>(
    socks5: A,
    socket: tokio::net::UdpSocket,
) -> Result<(UdpSocket, UdpSocketHolder)> {
    let addr = Address::Ip(socket.local_addr()?);
    let mut connector = Connector::new(socks5).await?;
    let mut peer_addr = connector.handshake(addr, CMD_UDP_ASSOCIATE).await?;

    if peer_addr.ip().is_unspecified() {
        peer_addr = SocketAddr::new(connector.stream.peer_addr()?.ip(), peer_addr.port());
    }

    Ok((
        UdpSocket::from(UdpSocketInner::from(socket), peer_addr),
        UdpSocketHolder::new(connector.stream),
    ))
}

struct Connector {
    stream: TcpStream,
}

impl Connector {
    async fn new<A: ToSocketAddrs>(addr: A) -> Result<Self> {
        let stream = TcpStream::connect(addr).await?;
        let mut connector = Self { stream };

        connector.select_method().await?;
        Ok(connector)
    }

    async fn select_method(&mut self) -> Result<()> {
        let request = [VER, 1, NO_AUTH];
        self.stream.write_all(&request).await?;

        let mut response = [0u8; 2];
        self.stream.read_exact(&mut response).await?;

        if response[0] != VER || response[1] != NO_AUTH {
            return Err(Error::new(ErrorKind::Other, "socks5: select method error"));
        }

        Ok(())
    }

    async fn handshake(&mut self, addr: Address, cmd: u8) -> Result<SocketAddr> {
        let mut request = [0u8; 3];
        request[0] = VER;
        request[1] = cmd;
        request[2] = 0;

        self.stream.write_all(&request).await?;
        addr.write(&mut self.stream).await?;

        let mut response = [0u8; 3];
        self.stream.read_exact(&mut response).await?;

        if response[0] != VER || response[1] != 0 {
            return Err(Error::new(ErrorKind::Other, "socks5: handshake error"));
        }

        if let Address::Ip(addr) = Address::read(&mut self.stream).await? {
            Ok(addr)
        } else {
            Err(Error::new(
                ErrorKind::Other,
                "socks5: handshake error, not addr responsed",
            ))
        }
    }
}
