use async_std::io;
use async_std::net::UdpSocket;
use async_std::task;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::vec::Vec;

use crate::ucp::internal::*;
use crate::ucp::metrics::*;
use crate::ucp::packet::*;
use crate::ucp::stream::*;

type UcpStreamMap = HashMap<SocketAddr, Arc<InnerStream>>;

pub struct UcpListener {
    socket: Arc<UdpSocket>,
    metrics: Box<dyn MetricsService>,
    stream_map: UcpStreamMap,
    timestamp: Instant,
}

impl UcpListener {
    pub async fn bind(listen_addr: &str, metrics: Box<dyn MetricsService>) -> Self {
        let socket = Arc::new(UdpSocket::bind(listen_addr).await.unwrap());
        UcpListener {
            socket,
            metrics,
            stream_map: UcpStreamMap::new(),
            timestamp: Instant::now(),
        }
    }

    pub async fn incoming(&mut self) -> UcpStream {
        loop {
            let mut packet = Box::new(UcpPacket::new());
            let result = io::timeout(
                Duration::from_secs(1),
                self.socket.recv_from(&mut packet.buf),
            )
            .await;

            if let Ok((size, remote_addr)) = result {
                packet.size = size;

                if packet.parse() {
                    if let Some(inner) = self.stream_map.get(&remote_addr) {
                        inner.input(packet, remote_addr).await;
                    } else if packet.is_syn() {
                        return self.new_stream(packet, remote_addr).await;
                    } else {
                        error!("unknown ucp session packet from {}", remote_addr);
                    }
                } else {
                    error!("recv illgal packet from {}", remote_addr);
                }
            }

            self.remove_dead_stream().await;
        }
    }

    async fn new_stream(&mut self, packet: Box<UcpPacket>, remote_addr: SocketAddr) -> UcpStream {
        info!("new ucp client from {}", remote_addr);
        let inner = Arc::new(InnerStream::new(
            self.socket.clone(),
            remote_addr,
            self.metrics.new_metrics_reporter(),
        ));
        inner.input(packet, remote_addr).await;

        let sender = inner.clone();
        task::spawn(async move {
            UcpStream::send(sender).await;
        });

        self.stream_map.insert(remote_addr, inner.clone());
        UcpStream { inner }
    }

    async fn remove_dead_stream(&mut self) {
        let now = Instant::now();
        if (now - self.timestamp).as_millis() < 1000 {
            return;
        }

        let mut keys = Vec::new();

        for (addr, stream) in self.stream_map.iter() {
            if !stream.alive() {
                keys.push(addr.clone());
            }
        }

        for addr in keys.iter() {
            self.stream_map.remove(addr);
        }

        self.timestamp = now;
    }
}
