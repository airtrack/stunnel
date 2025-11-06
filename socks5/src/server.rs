use std::io::{Error, ErrorKind, Result};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::proto::*;
use crate::udp::*;

pub async fn accept(stream: TcpStream) -> Result<AcceptResult> {
    let acceptor = Acceptor::new(stream);
    acceptor.accept().await
}

pub enum AcceptResult {
    Connect(TcpIncoming),
    UdpAssociate(UdpIncoming),
}

pub struct TcpIncoming {
    acceptor: Acceptor,
    addr: Address,
}

impl TcpIncoming {
    fn new(acceptor: Acceptor, addr: Address) -> Self {
        Self { acceptor, addr }
    }

    pub fn destination(&self) -> &Address {
        &self.addr
    }

    pub async fn reply_ok(mut self, bind: SocketAddr) -> Result<TcpStream> {
        self.acceptor.reply(true, bind).await?;
        Ok(self.acceptor.stream)
    }

    pub async fn reply_err(mut self) -> Result<()> {
        self.acceptor
            .reply(
                false,
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
            )
            .await
    }
}

pub struct UdpIncoming {
    socket: UdpSocketInner,
    holder: UdpSocketHolder,
}

impl UdpIncoming {
    fn new(socket: UdpSocketInner, holder: UdpSocketHolder) -> Self {
        Self { socket, holder }
    }

    pub async fn recv_wait(
        self,
        buf: &mut UdpSocketBuf,
    ) -> Result<(UdpSocket, UdpSocketHolder, SocketAddr)> {
        let (from, addr) = self.socket.recv(buf).await?;
        let socket = UdpSocket::from(self.socket, from);
        Ok((socket, self.holder, addr))
    }
}

struct Acceptor {
    stream: TcpStream,
}

impl Acceptor {
    fn new(stream: TcpStream) -> Self {
        Self { stream }
    }

    async fn accept(mut self) -> Result<AcceptResult> {
        self.select_method().await?;

        let mut req = [0u8; 3];
        self.stream.read_exact(&mut req).await?;
        match req[1] {
            CMD_CONNECT => self.accept_connect().await,
            CMD_UDP_ASSOCIATE => self.accept_udp_associate().await,
            c => {
                let error = format!("socks5: unknown CMD {}", c);
                Err(Error::new(ErrorKind::Other, error))
            }
        }
    }

    async fn accept_connect(mut self) -> Result<AcceptResult> {
        let addr = Address::read(&mut self.stream).await?;
        let incoming = TcpIncoming::new(self, addr);
        Ok(AcceptResult::Connect(incoming))
    }

    async fn accept_udp_associate(mut self) -> Result<AcceptResult> {
        let _ = Address::read(&mut self.stream).await?;
        let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
        self.reply(true, socket.local_addr()?).await?;

        let socket = UdpSocketInner::from(socket);
        let holder = UdpSocketHolder::new(self.stream);
        let incoming = UdpIncoming::new(socket, holder);
        Ok(AcceptResult::UdpAssociate(incoming))
    }

    async fn reply(&mut self, success: bool, bind: SocketAddr) -> Result<()> {
        let rep = if success {
            REP_SUCCESS
        } else {
            REP_HOST_UNREACHABLE
        };

        let ack = [VER, rep, 0];
        self.stream.write_all(&ack).await?;
        Address::Ip(bind).write(&mut self.stream).await
    }

    async fn select_method(&mut self) -> Result<()> {
        let mut buf = [0u8; 2];
        self.stream.read_exact(&mut buf).await?;

        if buf[0] != VER {
            return Err(Error::new(ErrorKind::Other, "socks5: VER error"));
        }

        let mut methods = vec![0u8; buf[1] as usize];
        self.stream.read_exact(&mut methods).await?;
        if !methods.into_iter().any(|m| m == NO_AUTH) {
            return Err(Error::new(
                ErrorKind::Other,
                "socks5: not found NO AUTH method",
            ));
        }

        let ack = [VER, NO_AUTH];
        self.stream.write_all(&ack).await
    }
}
