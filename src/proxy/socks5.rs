use std::{
    io::{Error, ErrorKind},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    ops::Range,
    sync::Arc,
};

use futures::future::abortable;
use log::{error, info};
use tokio::{
    io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    sync::oneshot,
};

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

pub enum Socks5Proxy {
    Connect {
        stream: Socks5TcpStream,
        host: String,
    },
    UdpAssociate {
        socket: Socks5UdpSocket,
        holder: TcpStream,
    },
}

impl Socks5Proxy {
    pub async fn accept(mut stream: TcpStream) -> std::io::Result<Self> {
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

    async fn accept_connect(mut stream: TcpStream, atype: u8) -> std::io::Result<Self> {
        let host = Self::parse_host(&mut stream, atype).await?;
        let stream = Socks5TcpStream::new(stream);
        Ok(Self::Connect { stream, host })
    }

    async fn accept_udp_associate(mut stream: TcpStream, atype: u8) -> std::io::Result<Self> {
        let _ = Self::parse_host(&mut stream, atype).await?;
        let socket = Socks5UdpSocket::new().await?;
        Self::reply(&mut stream, true, socket.socket.local_addr().unwrap()).await?;
        Ok(Self::UdpAssociate {
            socket,
            holder: stream,
        })
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
}

impl Socks5TcpStream {
    fn new(stream: TcpStream) -> Self {
        Self { stream }
    }

    pub async fn copy_bidirectional_tcp_stream(
        &mut self,
        other: &mut TcpStream,
    ) -> std::io::Result<(u64, u64)> {
        Socks5Proxy::reply(&mut self.stream, true, other.local_addr().unwrap()).await?;
        copy_bidirectional(&mut self.stream, other).await
    }
}

pub struct Socks5UdpSocket {
    socket: UdpSocket,
}

impl Socks5UdpSocket {
    async fn new() -> std::io::Result<Self> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        Ok(Self { socket })
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
        if let (Socks5Addr::IPv4(to), n) = Socks5Addr::parse(&buf[..size])
            .map_err(|_| Error::new(ErrorKind::Other, "Parse SOCKS5 udp packet error"))?
        {
            Ok((n..size, from, to))
        } else {
            Err(Error::new(
                ErrorKind::Other,
                "SOCKS5 addr from udp packet is not IPv4",
            ))
        }
    }

    pub async fn copy_bidirectional_udp_socket(
        self,
        other: UdpSocket,
        mut holder: TcpStream,
    ) -> std::io::Result<(u64, u64)> {
        let inbound1 = Arc::new(self);
        let outbound1 = Arc::new(other);
        let inbound2 = inbound1.clone();
        let outbound2 = outbound1.clone();
        let (tx, rx) = oneshot::channel();

        let (fut1, handle1) = abortable(async move {
            let mut buf = [0u8; 1500];
            let from1 = match inbound1.recv(&mut buf).await {
                Ok((range, from, to)) => {
                    let _ = outbound1.send_to(&buf[range], to).await;
                    info!("SOCKS5 UDP from {}", from);
                    from
                }
                Err(e) => {
                    error!("SOCKS5 UDP recv error {}", e);
                    return;
                }
            };

            match tx.send(from1) {
                Ok(_) => {}
                Err(_) => return,
            }

            loop {
                match inbound1.recv(&mut buf).await {
                    Ok((range, from2, to)) => {
                        if from1 == from2 {
                            let _ = outbound1.send_to(&buf[range], to).await;
                        } else {
                            error!("SOCKS5 UDP from addr not match {} != {}", from1, from2);
                        }
                    }
                    Err(e) => {
                        error!("SOCKS5 UDP recv from {} error {}", from1, e);
                    }
                }
            }
        });

        let (fut2, handle2) = abortable(async move {
            let to = match rx.await {
                Ok(to) => to,
                Err(_) => return,
            };

            let start = SOCKS5_IPV4_ADDR_LEN;
            let mut buf = [0u8; 1500];
            loop {
                match outbound2.recv_from(&mut buf[start..]).await {
                    Ok((size, from)) => {
                        match inbound2.send(&mut buf, start..start + size, from, to).await {
                            Ok(_) => {}
                            Err(e) => {
                                error!("SOCKS5 UDP from {} to {} error {}", from, to, e);
                            }
                        }
                    }
                    Err(_) => {}
                }
            }
        });

        tokio::spawn(fut1);
        tokio::spawn(fut2);

        loop {
            let mut buf = [0u8; 1024];
            match holder.read(&mut buf).await {
                Ok(0) | Err(_) => {
                    handle1.abort();
                    handle2.abort();
                    break;
                }
                Ok(_) => {}
            }
        }

        Ok((0, 0))
    }
}
