use std::io::{Error, ErrorKind, Result};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub(crate) const VER: u8 = 5;
pub(crate) const NO_AUTH: u8 = 0;

pub(crate) const CMD_CONNECT: u8 = 1;
pub(crate) const CMD_UDP_ASSOCIATE: u8 = 3;

pub(crate) const ATYP_IPV4: u8 = 1;
pub(crate) const ATYP_IPV6: u8 = 4;
pub(crate) const ATYP_DOMAIN: u8 = 3;

pub(crate) const REP_SUCCESS: u8 = 0;
pub(crate) const REP_HOST_UNREACHABLE: u8 = 4;

#[derive(Clone)]
pub enum Address {
    Host(String),
    Ip(SocketAddr),
}

impl Address {
    pub(crate) async fn read<R: AsyncReadExt + Unpin>(stream: &mut R) -> Result<Self> {
        let addr_type = stream.read_u8().await?;
        match addr_type {
            ATYP_IPV4 => {
                let ip = stream.read_u32().await?;
                let port = stream.read_u16().await?;
                let ip = Ipv4Addr::from_bits(ip);
                let addr = SocketAddrV4::new(ip, port);
                Ok(Self::Ip(SocketAddr::V4(addr)))
            }
            ATYP_IPV6 => {
                let ip = stream.read_u128().await?;
                let port = stream.read_u16().await?;
                let ip = Ipv6Addr::from_bits(ip);
                let addr = SocketAddrV6::new(ip, port, 0, 0);
                Ok(Self::Ip(SocketAddr::V6(addr)))
            }
            ATYP_DOMAIN => {
                let len = stream.read_u8().await?;
                let mut domain = vec![0u8; len as usize];
                stream.read_exact(&mut domain).await?;
                let port = stream.read_u16().await?;
                let host = String::from_utf8(domain)
                    .map_err(|_| Error::new(ErrorKind::Other, "socks5: invalid domain"))?;
                Ok(Self::Host(format!("{}:{}", host, port)))
            }
            addr_type => {
                let error = format!("socks5: unknown addr type {}", addr_type);
                Err(Error::new(ErrorKind::Other, error))
            }
        }
    }

    pub(crate) async fn write<W: AsyncWriteExt + Unpin>(&self, stream: &mut W) -> Result<()> {
        match self {
            Self::Ip(SocketAddr::V4(addr)) => {
                let mut request = [0u8; 7];

                request[0] = ATYP_IPV4;
                request[1..5].copy_from_slice(&addr.ip().octets());
                request[5..7].copy_from_slice(&addr.port().to_be_bytes());

                stream.write_all(&request).await?;
            }
            Self::Ip(SocketAddr::V6(addr)) => {
                let mut request = [0u8; 19];

                request[0] = ATYP_IPV6;
                request[1..17].copy_from_slice(&addr.ip().octets());
                request[17..19].copy_from_slice(&addr.port().to_be_bytes());

                stream.write_all(&request).await?;
            }
            Self::Host(host) => {
                let index = host
                    .rfind(':')
                    .ok_or(Error::new(ErrorKind::Other, "socks5: port not in host"))?;
                let port = host[index + 1..]
                    .parse()
                    .map_err(|e| Error::new(ErrorKind::Other, e))?;
                let host = host[..index].as_bytes();

                stream.write_u8(ATYP_DOMAIN).await?;
                stream.write_u8(host.len() as u8).await?;
                stream.write_all(host).await?;
                stream.write_u16(port).await?;
            }
        }

        Ok(())
    }
}
