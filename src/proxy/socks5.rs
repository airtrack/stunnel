use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use async_std::channel::{self, Receiver, Sender};
use async_std::io;
use async_std::net::{TcpStream, UdpSocket};
use async_std::prelude::*;
use async_trait::async_trait;

use crate::client::*;
use crate::protocol::{UdpDataPacker, UdpDataUnpacker};
use crate::proxy::{self, Destination, Proxy};

const VER: u8 = 5;
const RSV: u8 = 0;

const CMD_CONNECT: u8 = 1;
const CMD_UDP_ASSOCIATE: u8 = 3;

const METHOD_NO_AUTH: u8 = 0;
const METHOD_NO_ACCEPT: u8 = 0xFF;

const ATYP_IPV4: u8 = 1;
const ATYP_DOMAINNAME: u8 = 3;
const ATYP_IPV6: u8 = 4;

const REP_SUCCESS: u8 = 0;
const REP_FAILURE: u8 = 1;

struct UdpContext {
    socket: UdpSocket,
    alive: AtomicBool,
    tx: Sender<SocketAddr>,
    rx: Receiver<SocketAddr>,
}

pub struct Socks5 {
    udp_socks5: AtomicBool,
    udp: Option<UdpContext>,
}

#[async_trait]
impl Proxy for Socks5 {
    async fn handshake(&mut self, stream: &mut TcpStream) -> std::io::Result<Destination> {
        self.handshake_socks5(stream).await
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

    async fn proxy_tunnel_read(&self, stream: &mut &TcpStream, write_port: TunnelWritePort) {
        if self.udp_socks5.load(Ordering::Relaxed) {
            self.udp_proxy_tunnel_read(write_port).await;
        } else {
            proxy::proxy_tunnel_read(stream, write_port).await;
        }
    }

    async fn proxy_tunnel_write(&self, stream: &mut &TcpStream, read_port: TunnelReadPort) {
        if self.udp_socks5.load(Ordering::Relaxed) {
            let h = self.udp_proxy_connection_holder(stream);
            let w = self.udp_proxy_tunnel_write(read_port);
            h.join(w).await;
        } else {
            proxy::proxy_tunnel_write(stream, read_port).await;
        }
    }
}

impl Socks5 {
    pub fn new() -> Self {
        Self {
            udp_socks5: AtomicBool::new(false),
            udp: None,
        }
    }

    async fn handshake_socks5(&mut self, stream: &mut TcpStream) -> std::io::Result<Destination> {
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

        let cmd = buf[1];
        if cmd != CMD_CONNECT && cmd != CMD_UDP_ASSOCIATE {
            return Ok(Destination::Unknown);
        }

        let destination = match buf[3] {
            ATYP_IPV4 => {
                let mut ipv4_addr = [0u8; 6];
                stream.read_exact(&mut ipv4_addr).await?;

                let ipv4 = unsafe { *(ipv4_addr.as_ptr() as *const u32) };
                let port = unsafe { *(ipv4_addr.as_ptr().offset(4) as *const u16) };
                let addr = SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::from(u32::from_be(ipv4)),
                    u16::from_be(port),
                ));

                Destination::Address(addr)
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

        if cmd == CMD_CONNECT {
            return Ok(destination);
        }

        return self.handshake_udp_associate(destination).await;
    }

    async fn handshake_udp_associate(
        &mut self,
        destination: Destination,
    ) -> std::io::Result<Destination> {
        match destination {
            Destination::Address(_) => {}
            _ => {
                return Ok(Destination::Unknown);
            }
        };

        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let alive = AtomicBool::new(true);
        let local_addr = socket.local_addr()?;
        let (tx, rx) = channel::bounded(1);

        self.udp_socks5.store(true, Ordering::Relaxed);
        self.udp = Some(UdpContext {
            socket,
            alive,
            tx,
            rx,
        });

        return Ok(Destination::UdpAssociate(local_addr));
    }

    async fn udp_proxy_tunnel_read(&self, mut write_port: TunnelWritePort) {
        let udp_packer = UdpDataPacker;
        let udp = self.udp.as_ref().unwrap();
        let mut buf = [0; 1500];
        let mut send_addr = false;

        loop {
            if !udp.alive.load(Ordering::Relaxed) {
                break;
            }

            let result =
                io::timeout(Duration::from_millis(100), udp.socket.recv_from(&mut buf)).await;

            match result {
                Ok((n, source)) => {
                    if !send_addr {
                        let _ = udp.tx.send(source).await;
                        send_addr = true;
                    }

                    if let Some((data, dst_addr)) = unpack_socks5_udp_request(&buf[0..n]) {
                        let packed = udp_packer.pack_udp_data(&data, &dst_addr);
                        write_port.write(packed).await;
                    }
                }

                Err(_) => {}
            }
        }

        if !send_addr {
            let dummy = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(0), 0));
            let _ = udp.tx.send(dummy).await;
        }
        write_port.close().await;
    }

    async fn udp_proxy_tunnel_write(&self, mut read_port: TunnelReadPort) {
        let mut udp_unpacker = UdpDataUnpacker::new();
        let udp = self.udp.as_ref().unwrap();
        let client_addr = match udp.rx.recv().await {
            Ok(addr) => addr,
            Err(_) => return,
        };

        loop {
            if !udp.alive.load(Ordering::Relaxed) {
                break;
            }

            let udp_data = match read_port.read().await {
                TunnelPortMsg::Data(buf) => {
                    udp_unpacker.append_data(buf);
                    udp_unpacker.unpack_udp_data()
                }
                _ => break,
            };

            if let Some((data, source)) = udp_data {
                if let Some(buf) = pack_socks5_udp_request(&data, &source) {
                    let _ = udp.socket.send_to(&buf, client_addr).await;
                }
            }
        }

        read_port.drain();
    }

    async fn udp_proxy_connection_holder(&self, stream: &mut &TcpStream) {
        let mut buf = [0; 1024];

        loop {
            match stream.read(&mut buf).await {
                Ok(0) => break,
                Ok(_) => {}
                Err(_) => break,
            }
        }

        self.udp
            .as_ref()
            .unwrap()
            .alive
            .store(false, Ordering::Relaxed);
    }
}

fn pack_socks5_udp_request(data: &[u8], addr: &SocketAddr) -> Option<Vec<u8>> {
    match addr {
        SocketAddr::V4(ipv4) => {
            let mut buf = vec![0u8; 10 + data.len()];
            buf[3] = ATYP_IPV4;
            unsafe {
                *(buf.as_ptr().offset(4) as *mut u32) = u32::from(ipv4.ip().clone()).to_be();
                *(buf.as_ptr().offset(8) as *mut u16) = ipv4.port().to_be();
            }

            buf[10..].copy_from_slice(data);
            return Some(buf);
        }

        _ => return None,
    }
}

fn unpack_socks5_udp_request(buf: &[u8]) -> Option<(Vec<u8>, SocketAddr)> {
    if buf.len() < 10 {
        return None;
    }

    if buf[3] != ATYP_IPV4 {
        return None;
    }

    let ipv4_addr = &buf[4..10];
    let ipv4 = unsafe { *(ipv4_addr.as_ptr() as *const u32) };
    let port = unsafe { *(ipv4_addr.as_ptr().offset(4) as *const u16) };
    let addr = SocketAddr::V4(SocketAddrV4::new(
        Ipv4Addr::from(u32::from_be(ipv4)),
        u16::from_be(port),
    ));

    let data = &buf[10..];
    return Some((data.iter().cloned().collect(), addr));
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
