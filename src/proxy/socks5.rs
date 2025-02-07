use std::{
    io::{Error, ErrorKind},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    ops::Range,
};

use async_trait::async_trait;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    sync::oneshot::{self, Receiver, Sender},
};

use super::{AsyncReadDatagram, AsyncWriteDatagram, Proxy, ProxyType, TcpProxyConn, UdpProxyBind};

const SOCKS5_VER: u8 = 5;
const METHOD_NO_AUTH: u8 = 0;

const CMD_CONNECT: u8 = 1;
const CMD_UDP_ASSOCIATE: u8 = 3;

const ADDR_TYPE_IPV4: u8 = 1;
const ADDR_TYPE_IPV6: u8 = 4;
const ADDR_TYPE_DOMAIN: u8 = 3;

const REP_SUCCESS: u8 = 0;
const REP_HOST_UNREACHABLE: u8 = 4;

const SOCKS5_IPV4_ADDR_LEN: usize = 10;

enum Socks5Addr {
    IPv4(SocketAddr),
    Host(String),
}

struct Socks5AddrError;

impl Socks5Addr {
    fn parse(buf: &[u8]) -> Result<(Self, usize), Socks5AddrError> {
        if buf.len() < SOCKS5_IPV4_ADDR_LEN {
            return Err(Socks5AddrError);
        }

        match buf[3] {
            ADDR_TYPE_IPV4 => {
                let ipv4 = Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
                let bytes = [buf[8], buf[9]];
                let port = u16::from_be_bytes(bytes);
                let addr = SocketAddrV4::new(ipv4, port);
                Ok((Socks5Addr::IPv4(SocketAddr::V4(addr)), SOCKS5_IPV4_ADDR_LEN))
            }
            ADDR_TYPE_IPV6 => Err(Socks5AddrError),
            ADDR_TYPE_DOMAIN => {
                let len = buf[4] as usize;
                if buf.len() < 4 + 1 + len + 2 {
                    return Err(Socks5AddrError);
                }

                let domain: Vec<u8> = buf[5..5 + len].iter().copied().collect();
                let host = String::from_utf8(domain).map_err(|_| Socks5AddrError)?;
                let bytes = [buf[5 + len], buf[6 + len]];
                let port = u16::from_be_bytes(bytes);
                let host = format!("{}:{}", host, port);
                Ok((Socks5Addr::Host(host), 7 + len))
            }
            _ => Err(Socks5AddrError),
        }
    }

    fn to_slice(&self, buf: &mut [u8]) -> Result<usize, Socks5AddrError> {
        match self {
            Socks5Addr::IPv4(SocketAddr::V4(addr)) => {
                if buf.len() < SOCKS5_IPV4_ADDR_LEN {
                    return Err(Socks5AddrError);
                }

                buf[0] = 0;
                buf[1] = 0;
                buf[2] = 0;
                buf[3] = ADDR_TYPE_IPV4;
                buf[4..8].copy_from_slice(&addr.ip().octets());
                buf[8..10].copy_from_slice(&addr.port().to_be_bytes());

                Ok(SOCKS5_IPV4_ADDR_LEN)
            }
            _ => Err(Socks5AddrError),
        }
    }
}

#[derive(Clone, Copy)]
pub struct Socks5Proxy;

#[async_trait]
impl Proxy<Socks5TcpStream, Socks5UdpSocket> for Socks5Proxy {
    async fn accept(
        &self,
        stream: TcpStream,
    ) -> std::io::Result<ProxyType<Socks5TcpStream, Socks5UdpSocket>> {
        Ok(Self::accept(stream).await?)
    }
}

impl Socks5Proxy {
    pub async fn accept(
        mut stream: TcpStream,
    ) -> std::io::Result<ProxyType<Socks5TcpStream, Socks5UdpSocket>> {
        Self::select_method(&mut stream).await?;

        let mut req = [0u8; 4];
        stream.read_exact(&mut req).await?;
        match req[1] {
            CMD_CONNECT => Self::accept_connect(stream, req[3]).await,
            CMD_UDP_ASSOCIATE => Self::accept_udp_associate(stream, req[3]).await,
            c => {
                let error = format!("Unsupport SOCKS5 CMD {}", c);
                Err(Error::new(ErrorKind::Other, error))
            }
        }
    }

    async fn reply(stream: &mut TcpStream, success: bool, bind: SocketAddr) -> std::io::Result<()> {
        let rep = if success {
            REP_SUCCESS
        } else {
            REP_HOST_UNREACHABLE
        };
        let addr_type = if bind.is_ipv4() {
            ADDR_TYPE_IPV4
        } else {
            ADDR_TYPE_IPV6
        };

        let ack = [SOCKS5_VER, rep, 0, addr_type];
        stream.write_all(&ack).await?;

        match bind {
            SocketAddr::V4(addr) => {
                stream.write_all(&addr.ip().octets()).await?;
                stream.write_u16(addr.port()).await
            }
            SocketAddr::V6(addr) => {
                stream.write_all(&addr.ip().octets()).await?;
                stream.write_u16(addr.port()).await
            }
        }
    }

    async fn select_method(stream: &mut TcpStream) -> std::io::Result<()> {
        let mut buf = [0u8; 2];
        stream.read_exact(&mut buf).await?;

        if buf[0] != SOCKS5_VER {
            return Err(Error::new(ErrorKind::Other, "SOCKS5 VER error"));
        }

        let mut methods = vec![0u8; buf[1] as usize];
        stream.read_exact(&mut methods).await?;
        if !methods.into_iter().any(|m| m == METHOD_NO_AUTH) {
            return Err(Error::new(ErrorKind::Other, "Not found NO AUTH method"));
        }

        let ack = [SOCKS5_VER, METHOD_NO_AUTH];
        stream.write_all(&ack).await
    }

    async fn accept_connect(
        mut stream: TcpStream,
        atype: u8,
    ) -> std::io::Result<ProxyType<Socks5TcpStream, Socks5UdpSocket>> {
        let host = Self::parse_host(&mut stream, atype).await?;
        let stream = Socks5TcpStream::new(stream, host);
        Ok(ProxyType::Tcp(stream))
    }

    async fn accept_udp_associate(
        mut stream: TcpStream,
        atype: u8,
    ) -> std::io::Result<ProxyType<Socks5TcpStream, Socks5UdpSocket>> {
        Self::parse_host(&mut stream, atype).await?;
        let socket = Socks5UdpSocket::new(stream).await?;
        Ok(ProxyType::Udp(socket))
    }

    async fn parse_host(stream: &mut TcpStream, atype: u8) -> std::io::Result<String> {
        let host = match atype {
            ADDR_TYPE_IPV4 => {
                let mut octets = [0u8; 4];
                stream.read_exact(&mut octets).await?;
                let port = stream.read_u16().await?;
                format!(
                    "{}.{}.{}.{}:{}",
                    octets[0], octets[1], octets[2], octets[3], port
                )
            }
            ADDR_TYPE_DOMAIN => {
                let len = stream.read_u8().await?;
                let mut domain = vec![0u8; len as usize];
                stream.read_exact(&mut domain).await?;
                let port = stream.read_u16().await?;
                let host = String::from_utf8(domain)
                    .map_err(|_| Error::new(ErrorKind::Other, "Domain is invalid"))?;
                format!("{}:{}", host, port)
            }
            ADDR_TYPE_IPV6 => {
                let error = format!("IPv6 address is not support");
                return Err(Error::new(ErrorKind::Other, error));
            }
            addr_type => {
                let error = format!("Unsupport SOCKS5 addr type {}", addr_type);
                return Err(Error::new(ErrorKind::Other, error));
            }
        };

        Ok(host)
    }
}

pub struct Socks5TcpStream {
    stream: TcpStream,
    host: String,
}

impl Socks5TcpStream {
    fn new(stream: TcpStream, host: String) -> Self {
        Self { stream, host }
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub async fn connect_ok(&mut self, bind: SocketAddr) -> std::io::Result<()> {
        Socks5Proxy::reply(&mut self.stream, true, bind).await
    }

    pub async fn connect_err(&mut self) -> std::io::Result<()> {
        Socks5Proxy::reply(&mut self.stream, false, "0.0.0.0:0".parse().unwrap()).await?;
        self.stream.shutdown().await
    }

    pub async fn copy_bidirectional<
        R: AsyncRead + Unpin + ?Sized,
        W: AsyncWrite + Unpin + ?Sized,
    >(
        &mut self,
        reader: &mut R,
        writer: &mut W,
    ) -> std::io::Result<(u64, u64)> {
        super::copy_bidirectional(&mut self.stream, reader, writer).await
    }
}

#[async_trait]
impl TcpProxyConn for Socks5TcpStream {
    fn target_host(&self) -> &str {
        self.host()
    }

    async fn response_connect_ok(&mut self, bind: SocketAddr) -> std::io::Result<()> {
        self.connect_ok(bind).await
    }

    async fn response_connect_err(&mut self) -> std::io::Result<()> {
        self.connect_err().await
    }

    async fn copy_bidirectional<
        R: AsyncRead + Send + Unpin + ?Sized,
        W: AsyncWrite + Send + Unpin + ?Sized,
    >(
        &mut self,
        reader: &mut R,
        writer: &mut W,
    ) -> std::io::Result<(u64, u64)> {
        self.copy_bidirectional(reader, writer).await
    }
}

pub struct Socks5UdpSocket {
    socket: UdpSocket,
    holder: Option<TcpStream>,
}

impl Socks5UdpSocket {
    async fn new(holder: TcpStream) -> std::io::Result<Self> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        Ok(Self {
            socket,
            holder: Some(holder),
        })
    }

    fn split(self) -> (Self, TcpStream) {
        (
            Self {
                socket: self.socket,
                holder: None,
            },
            self.holder.unwrap(),
        )
    }

    pub async fn associate_ok(&mut self) -> std::io::Result<()> {
        Socks5Proxy::reply(
            self.holder.as_mut().unwrap(),
            true,
            self.socket.local_addr().unwrap(),
        )
        .await
    }

    pub async fn associate_err(&mut self) -> std::io::Result<()> {
        Socks5Proxy::reply(
            self.holder.as_mut().unwrap(),
            false,
            "0.0.0.0:0".parse().unwrap(),
        )
        .await?;
        self.holder.as_mut().unwrap().shutdown().await
    }

    pub async fn copy_bidirectional(
        self,
        reader: impl AsyncReadDatagram,
        writer: impl AsyncWriteDatagram,
    ) -> std::io::Result<()> {
        let (tx, rx) = oneshot::channel();
        let (this, holder) = self.split();

        let r = this.copy_read(reader, rx);
        let w = this.copy_write(writer, tx);
        let h = Self::copy_holder(holder);

        futures::try_join!(r, w, h)?;
        Ok(())
    }

    async fn send(
        &self,
        buf: &mut [u8],
        range: Range<usize>,
        from: SocketAddr,
        to: SocketAddr,
    ) -> std::io::Result<usize> {
        let addr = Socks5Addr::IPv4(from);
        addr.to_slice(&mut buf[..range.start])
            .map_err(|_| Error::new(ErrorKind::Other, "SOCKS5 addr error"))?;
        self.socket.send_to(&buf[..range.end], to).await
    }

    async fn recv(
        &self,
        buf: &mut [u8],
    ) -> std::io::Result<(Range<usize>, SocketAddr, SocketAddr)> {
        let (size, from) = self.socket.recv_from(&mut buf[..]).await?;
        let (addr, n) = Socks5Addr::parse(&buf[..size])
            .map_err(|_| Error::new(ErrorKind::Other, "Parse SOCKS5 udp packet error"))?;

        match addr {
            Socks5Addr::IPv4(to) => Ok((n..size, from, to)),
            Socks5Addr::Host(host) => Err(Error::new(
                ErrorKind::Other,
                format!("SOCKS5 addr {} from udp packet is not IPv4", host),
            )),
        }
    }

    async fn copy_write(
        &self,
        mut writer: impl AsyncWriteDatagram,
        tx: Sender<SocketAddr>,
    ) -> std::io::Result<()> {
        let mut buf = [0u8; 1500];
        let (range, from1, to) = self.recv(&mut buf).await?;
        writer.send(&buf[range], to).await?;

        tx.send(from1)
            .map_err(|_| Error::new(ErrorKind::Other, "Send addr error"))?;

        loop {
            let (range, from2, to) = self.recv(&mut buf).await?;
            if from1 == from2 {
                writer.send(&buf[range], to).await?;
            }
        }
    }

    async fn copy_read(
        &self,
        mut reader: impl AsyncReadDatagram,
        rx: Receiver<SocketAddr>,
    ) -> std::io::Result<()> {
        let to = rx
            .await
            .map_err(|error| Error::new(ErrorKind::Other, error))?;

        const START: usize = SOCKS5_IPV4_ADDR_LEN;
        let mut buf = [0u8; 1500];
        loop {
            let (size, from) = reader.recv(&mut buf[START..]).await?;
            self.send(&mut buf, START..START + size, from, to).await?;
        }
    }

    async fn copy_holder(mut holder: TcpStream) -> std::io::Result<()> {
        let mut buf = [0u8; 1024];

        loop {
            if holder.read(&mut buf).await? == 0 {
                return Err(Error::new(
                    ErrorKind::ConnectionAborted,
                    "Tcp holder disconnected",
                ));
            }
        }
    }
}

#[async_trait]
impl UdpProxyBind for Socks5UdpSocket {
    async fn response_bind_ok(&mut self) -> std::io::Result<()> {
        self.associate_ok().await
    }

    async fn response_bind_err(&mut self) -> std::io::Result<()> {
        self.associate_err().await
    }

    async fn copy_bidirectional(
        self,
        reader: impl AsyncReadDatagram + Send,
        writer: impl AsyncWriteDatagram + Send,
    ) -> std::io::Result<()> {
        self.copy_bidirectional(reader, writer).await
    }
}
