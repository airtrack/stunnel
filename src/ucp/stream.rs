use std::net::SocketAddr;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use async_std::io::{self, Read, Write};
use async_std::net::UdpSocket;
use async_std::task;

use crate::ucp::internal::*;
use crate::ucp::metrics::MetricsReporter;
use crate::ucp::packet::*;
use crate::ucp::*;

pub struct UcpStream {
    pub(super) inner: Arc<InnerStream>,
}

impl UcpStream {
    pub async fn connect(server_addr: &str, metrics_reporter: Box<dyn MetricsReporter>) -> Self {
        let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await.unwrap());
        let remote_addr = SocketAddr::from_str(server_addr).unwrap();

        let inner = Arc::new(InnerStream::new(socket, remote_addr, metrics_reporter));
        inner.connecting();

        let sender = inner.clone();
        task::spawn(async move {
            UcpStream::send(sender).await;
        });

        let receiver = inner.clone();
        task::spawn(async move {
            UcpStream::recv(receiver).await;
        });

        UcpStream { inner: inner }
    }

    pub fn shutdown(&self) {
        self.inner.shutdown();
    }

    pub(super) async fn send(inner: Arc<InnerStream>) {
        loop {
            task::sleep(PACING_INTERVAL).await;
            inner.output().await;

            if !inner.alive() {
                break;
            }
        }
    }

    async fn recv(inner: Arc<InnerStream>) {
        loop {
            let mut packet = Box::new(UcpPacket::new());
            let result = io::timeout(
                Duration::from_secs(5),
                inner.socket.recv_from(&mut packet.buf),
            )
            .await;

            if !inner.alive() {
                break;
            }

            if let Ok((size, remote_addr)) = result {
                packet.size = size;

                if packet.parse() {
                    inner.input(packet, remote_addr).await;
                } else {
                    error!("recv illgal packet from {}", remote_addr);
                }
            }
        }
    }
}

impl Read for &UcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        self.inner.poll_read(cx, buf)
    }
}

impl Write for &UcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.inner.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
