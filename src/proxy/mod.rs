use std::net::{Shutdown, SocketAddr, ToSocketAddrs};
use std::str::from_utf8;

use async_std::net::TcpStream;
use async_std::prelude::*;
use async_trait::async_trait;

use crate::client::*;

pub mod http;
pub mod socks5;

pub enum Destination {
    Address(SocketAddr),
    DomainName(Vec<u8>, u16),
    UdpAssociate(SocketAddr),
    Unknown,
}

#[async_trait]
pub trait Proxy: Sync {
    async fn handshake(&mut self, stream: &mut TcpStream) -> std::io::Result<Destination>;
    async fn destination_unreached(&self, stream: &mut TcpStream) -> std::io::Result<()>;
    async fn destination_connected(
        &self,
        stream: &mut TcpStream,
        bind_addr: SocketAddr,
    ) -> std::io::Result<()>;

    async fn proxy_tunnel_read(&self, stream: &mut &TcpStream, write_port: TunnelWritePort) {
        proxy_tunnel_read(stream, write_port).await;
    }

    async fn proxy_tunnel_write(&self, stream: &mut &TcpStream, read_port: TunnelReadPort) {
        proxy_tunnel_write(stream, read_port).await;
    }

    async fn run_proxy_tunnel(
        &mut self,
        mut stream: TcpStream,
        mut read_port: TunnelReadPort,
        mut write_port: TunnelWritePort,
    ) {
        match self.handshake(&mut stream).await {
            Ok(Destination::Address(addr)) => {
                let mut buf = Vec::new();
                let _ = std::io::Write::write_fmt(&mut buf, format_args!("{}", addr));
                write_port.connect(buf).await;
            }

            Ok(Destination::DomainName(domain_name, port)) => {
                write_port.connect_domain_name(domain_name, port).await;
            }

            Ok(Destination::UdpAssociate(addr)) => {
                let mut buf = Vec::new();
                let _ = std::io::Write::write_fmt(&mut buf, format_args!("{}", addr));
                write_port.udp_associate(buf).await;
            }

            _ => {
                return write_port.close().await;
            }
        }

        let addr = match read_port.read().await {
            TunnelPortMsg::ConnectOk(buf) => {
                from_utf8(&buf).unwrap().to_socket_addrs().unwrap().nth(0)
            }

            _ => None,
        };

        let success = match addr {
            Some(addr) => self.destination_connected(&mut stream, addr).await.is_ok(),
            None => self.destination_unreached(&mut stream).await.is_ok() && false,
        };

        if success {
            let (reader, writer) = &mut (&stream, &stream);
            let r = self.proxy_tunnel_read(reader, write_port);
            let w = self.proxy_tunnel_write(writer, read_port);
            let _ = r.join(w).await;
        } else {
            let _ = stream.shutdown(Shutdown::Both);
            read_port.drain();
            write_port.close().await;
        }
    }
}

async fn proxy_tunnel_read(stream: &mut &TcpStream, mut write_port: TunnelWritePort) {
    loop {
        let mut buf = vec![0; 1024];
        match stream.read(&mut buf).await {
            Ok(0) => {
                let _ = stream.shutdown(Shutdown::Read);
                write_port.shutdown_write().await;
                write_port.drop().await;
                break;
            }

            Ok(n) => {
                buf.truncate(n);
                write_port.write(buf).await;
            }

            Err(_) => {
                let _ = stream.shutdown(Shutdown::Both);
                write_port.close().await;
                break;
            }
        }
    }
}

async fn proxy_tunnel_write(stream: &mut &TcpStream, mut read_port: TunnelReadPort) {
    loop {
        let buf = match read_port.read().await {
            TunnelPortMsg::Data(buf) => buf,

            TunnelPortMsg::ShutdownWrite => {
                let _ = stream.shutdown(Shutdown::Write);
                read_port.drain();
                read_port.drop().await;
                break;
            }

            _ => {
                let _ = stream.shutdown(Shutdown::Both);
                read_port.drain();
                read_port.close().await;
                break;
            }
        };

        if stream.write_all(&buf).await.is_err() {
            let _ = stream.shutdown(Shutdown::Both);
            read_port.drain();
            read_port.close().await;
            break;
        }
    }
}
