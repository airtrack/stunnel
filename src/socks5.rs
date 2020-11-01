use crate::proxy::{Destination, Proxy};
use async_std::net::TcpStream;
use async_std::prelude::*;
use async_trait::async_trait;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

const VER: u8 = 5;
const RSV: u8 = 0;

const CMD_CONNECT: u8 = 1;
const METHOD_NO_AUTH: u8 = 0;
const METHOD_NO_ACCEPT: u8 = 0xFF;

const ATYP_IPV4: u8 = 1;
const ATYP_DOMAINNAME: u8 = 3;
const ATYP_IPV6: u8 = 4;

const REP_SUCCESS: u8 = 0;
const REP_FAILURE: u8 = 1;

pub struct Socks5;

#[async_trait]
impl Proxy for Socks5 {
    async fn handshake(&self, stream: &mut TcpStream) -> std::io::Result<Destination> {
        handshake(stream).await
    }

    async fn destination_unreached(&self, stream: &mut TcpStream) -> std::io::Result<()> {
        destination_unreached(stream).await
    }

    async fn destination_connected(
        &self,
        stream: &mut TcpStream,
        bind_addr: SocketAddr,
    ) -> std::io::Result<()> {
        destination_connected(stream, bind_addr).await
    }
}

async fn handshake(stream: &mut TcpStream) -> std::io::Result<Destination> {
    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf).await?;

    if buf[0] != VER {
        choose_method(stream, METHOD_NO_ACCEPT).await?;
        return Ok(Destination::Unknown);
    }

    let mut methods = vec![0; buf[1] as usize];
    stream.read_exact(&mut methods).await?;

    if !methods.into_iter().any(|method| method == METHOD_NO_AUTH) {
        choose_method(stream, METHOD_NO_ACCEPT).await?;
        return Ok(Destination::Unknown);
    }

    choose_method(stream, METHOD_NO_AUTH).await?;

    let mut buf = [0u8; 4];
    stream.read_exact(&mut buf).await?;

    if buf[1] != CMD_CONNECT {
        return Ok(Destination::Unknown);
    }

    let destination = match buf[3] {
        ATYP_IPV4 => {
            let mut ipv4_addr = [0u8; 6];
            stream.read_exact(&mut ipv4_addr).await?;

            let port = unsafe { *(ipv4_addr.as_ptr().offset(4) as *const u16) };
            Destination::Address(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(ipv4_addr[3], ipv4_addr[2], ipv4_addr[1], ipv4_addr[0]),
                u16::from_be(port),
            )))
        }

        ATYP_DOMAINNAME => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;

            let len = len[0] as usize;
            let mut buf = vec![0u8; len + 2];
            stream.read_exact(&mut buf).await?;

            let port = unsafe { *(buf.as_ptr().offset(len as isize) as *const u16) };
            buf.truncate(len);
            Destination::DomainName(buf, u16::from_be(port))
        }

        ATYP_IPV6 => Destination::Unknown,
        _ => Destination::Unknown,
    };

    Ok(destination)
}

async fn destination_unreached(stream: &mut TcpStream) -> std::io::Result<()> {
    let bind_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));
    destination_result(stream, bind_addr, REP_FAILURE).await
}

async fn destination_connected(
    stream: &mut TcpStream,
    bind_addr: SocketAddr,
) -> std::io::Result<()> {
    destination_result(stream, bind_addr, REP_SUCCESS).await
}

async fn choose_method(stream: &mut TcpStream, method: u8) -> std::io::Result<()> {
    let buf = [VER, method];
    stream.write_all(&buf).await
}

async fn destination_result(
    stream: &mut TcpStream,
    bind_addr: SocketAddr,
    rsp: u8,
) -> std::io::Result<()> {
    match bind_addr {
        SocketAddr::V4(ipv4) => {
            let mut buf = [0u8; 10];

            buf[0] = VER;
            buf[1] = rsp;
            buf[2] = RSV;
            buf[3] = ATYP_IPV4;
            unsafe {
                *(buf.as_ptr().offset(4) as *mut u32) = u32::from(ipv4.ip().clone()).to_be();
                *(buf.as_ptr().offset(8) as *mut u16) = ipv4.port().to_be();
            }

            stream.write_all(&buf).await?
        }

        SocketAddr::V6(ipv6) => {
            let mut buf = [0u8; 22];

            buf[0] = VER;
            buf[1] = rsp;
            buf[2] = RSV;
            buf[3] = ATYP_IPV6;
            unsafe {
                *(buf.as_ptr().offset(4) as *mut u128) = u128::from(ipv6.ip().clone()).to_be();
                *(buf.as_ptr().offset(20) as *mut u16) = ipv6.port().to_be();
            }

            stream.write_all(&buf).await?
        }
    }

    Ok(())
}
