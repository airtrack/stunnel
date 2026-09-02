use std::net::SocketAddr;

use log::error;
use socks5::{AcceptResult, Address, UdpSocket, UdpSocketBuf, UdpSocketHolder};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream};

use crate::tunnel::{
    AcceptTunnel, AsyncReadDatagramExt, AsyncWriteDatagramExt, OpenTunnel,
    client::{ReverseTunnel, connect_tcp_tunnel, connect_udp_tunnel, run_reverse_tunnels},
};

trait IoErrorContext<T> {
    fn context(self, msg: &str) -> std::io::Result<T>;
}

impl<T> IoErrorContext<T> for std::io::Result<T> {
    fn context(self, msg: &str) -> std::io::Result<T> {
        self.map_err(|error| std::io::Error::new(error.kind(), format!("{msg}: {error}")))
    }
}

pub async fn run_all_kinds_tunnels<O, A, D>(
    opener: O,
    acceptor: A,
    reverse_tunnels: &[ReverseTunnel],
    http_listener: &TcpListener,
    socks5_listener: &TcpListener,
    id: D,
) -> std::io::Result<()>
where
    O: OpenTunnel,
    A: AcceptTunnel,
    D: std::fmt::Display + Copy + Send + 'static,
{
    let reverse = run_reverse_tunnels(opener.clone(), acceptor, reverse_tunnels);
    let h = accept_http_tunnels(http_listener, &opener, id);
    let s = accept_socks5_tunnels(socks5_listener, &opener, id);

    futures::try_join!(h, s, reverse).map(|_| ())
}

pub async fn accept_http_tunnels<O, D>(
    listener: &TcpListener,
    opener: &O,
    id: D,
) -> std::io::Result<()>
where
    O: OpenTunnel,
    D: std::fmt::Display + Copy + Send + 'static,
{
    loop {
        let (stream, _) = listener.accept().await?;

        let id = id;
        let opener = opener.clone();

        tokio::spawn(async move {
            run_http_tunnel(stream, opener)
                .await
                .inspect_err(|error| {
                    error!("http proxy connection(on underlying {id}) error: {error}");
                })
                .ok();
        });
    }
}

async fn run_http_tunnel<O>(stream: TcpStream, opener: O) -> std::io::Result<()>
where
    O: OpenTunnel,
{
    let incoming = httpproxy::accept(stream).await?;
    let host = incoming.host().to_string();

    match connect_tcp_tunnel(opener, &host).await {
        Ok((_, mut tun)) => {
            let (mut stream, req) = incoming.response_200().await.context(&host)?;
            if let Some(req) = req {
                tun.write_all(&req).await.context(&host)?;
            }
            copy_bidirectional(&mut stream, &mut tun)
                .await
                .context(&host)?;
        }
        Err(error) => {
            incoming.response_404().await.context(&host)?;
            return Err(error).context(&host);
        }
    }

    Ok(())
}

pub async fn accept_socks5_tunnels<O, D>(
    listener: &TcpListener,
    opener: &O,
    id: D,
) -> std::io::Result<()>
where
    O: OpenTunnel,
    D: std::fmt::Display + Copy + Send + 'static,
{
    loop {
        let (stream, _) = listener.accept().await?;

        let id = id;
        let opener = opener.clone();

        tokio::spawn(async move {
            run_socks5_tunnel(stream, opener)
                .await
                .inspect_err(|error| {
                    error!("socks5 proxy connection(on underlying {id}) error: {error}");
                })
                .ok();
        });
    }
}

async fn run_socks5_tunnel<O>(stream: TcpStream, opener: O) -> std::io::Result<()>
where
    O: OpenTunnel,
{
    match socks5::accept(stream).await? {
        AcceptResult::Connect(incoming) => {
            let target = match incoming.destination() {
                Address::Host(host) => host.clone(),
                Address::Ip(addr) => addr.to_string(),
            };

            match connect_tcp_tunnel(opener, &target).await {
                Ok((bind, mut tun)) => {
                    let mut stream = incoming.reply_ok(bind).await.context(&target)?;
                    copy_bidirectional(&mut stream, &mut tun)
                        .await
                        .context(&target)?;
                }
                Err(error) => {
                    incoming.reply_err().await.context(&target)?;
                    return Err(error).context(&target);
                }
            }
        }
        AcceptResult::UdpAssociate(incoming) => {
            let mut buf = UdpSocketBuf::new();
            let (socket, holder, dst) = incoming.recv_wait(&mut buf).await?;

            let tun = connect_udp_tunnel(opener).await?;
            let (send, recv) = tun.split();

            async fn s<S>(
                socket: &UdpSocket,
                mut send: S,
                mut buf: UdpSocketBuf,
                addr: SocketAddr,
            ) -> std::io::Result<()>
            where
                S: AsyncWrite + Send + Unpin,
            {
                send.send_datagram(buf.as_ref(), addr).await?;
                loop {
                    let addr = socket.recv(&mut buf).await?;
                    send.send_datagram(buf.as_ref(), addr).await?;
                }
            }

            async fn r<R>(socket: &UdpSocket, mut recv: R) -> std::io::Result<()>
            where
                R: AsyncRead + Send + Unpin,
            {
                let mut buf = UdpSocketBuf::new();
                loop {
                    let (n, addr) = recv.recv_datagram(buf.as_mut()).await?;
                    buf.set_len(n);
                    socket.send(&mut buf, addr).await?;
                }
            }

            async fn h(mut holder: UdpSocketHolder) -> std::io::Result<()> {
                holder.wait().await
            }

            futures::try_join!(s(&socket, send, buf, dst), r(&socket, recv), h(holder))?;
        }
    }

    Ok(())
}
