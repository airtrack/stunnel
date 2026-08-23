use std::net::SocketAddr;

use log::{error, info};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, copy_bidirectional};
use tokio::net::TcpStream;

use crate::tunnel::{
    AcceptTunnel, ControlReply, OpenTunnel, TYPE_CONTROL, TYPE_TCP_FWD, TYPE_TCP_REV, TYPE_UDP_FWD,
    Tunnel,
};

#[derive(Clone)]
pub struct ReverseTunnel {
    pub listen: String,
    pub target: String,
}

pub async fn connect_tcp_tunnel<O>(
    mut opener: O,
    target: &str,
) -> std::io::Result<(SocketAddr, Tunnel<O::S, O::R>)>
where
    O: OpenTunnel,
{
    let mut tun = opener.open_tunnel().await?;

    tun.write_u8(TYPE_TCP_FWD).await?;
    tun.write_str8(target).await?;

    let bind = tun.read_str8().await?;
    let bind = bind.parse::<SocketAddr>().map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid bind addr: {error}"),
        )
    })?;

    Ok((bind, tun))
}

pub async fn connect_udp_tunnel<O>(mut opener: O) -> std::io::Result<Tunnel<O::S, O::R>>
where
    O: OpenTunnel,
{
    let mut tun = opener.open_tunnel().await?;

    tun.write_u8(TYPE_UDP_FWD).await?;

    // server responds with its udp socket bind addr, not used by the caller
    tun.read_str8().await?;

    Ok(tun)
}

// Runs the reverse side of one multiplexed connection: registers the
// configured listeners and handles server-initiated reverse tunnels.
pub async fn run_reverse_tunnels<O, A>(
    opener: O,
    acceptor: A,
    reverse_tunnels: &[ReverseTunnel],
) -> std::io::Result<()>
where
    O: OpenTunnel,
    A: AcceptTunnel,
{
    let control = run_control_tunnel(opener, reverse_tunnels);
    let reverse = accept_reverse_tunnels(acceptor);

    futures::try_join!(control, reverse).map(|_| ())
}

// Registers the reverse proxies on the server over the control tunnel, then
// holds the control tunnel open until the connection dies.
async fn run_control_tunnel<O>(
    mut opener: O,
    reverse_tunnels: &[ReverseTunnel],
) -> std::io::Result<()>
where
    O: OpenTunnel,
{
    if reverse_tunnels.is_empty() {
        return std::future::pending().await;
    }

    let mut tun = opener.open_tunnel().await?;

    tun.write_u8(TYPE_CONTROL).await?;
    register_reverse_tunnels(&mut tun, reverse_tunnels).await?;
    tun.send_register_reverse_end().await?;

    let mut buf = [0u8; 64];
    loop {
        let n = tun.read(&mut buf).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "control tunnel closed",
            ));
        }
    }
}

async fn register_reverse_tunnels<S, R>(
    tun: &mut Tunnel<S, R>,
    reverse_tunnels: &[ReverseTunnel],
) -> std::io::Result<()>
where
    S: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    for rp in reverse_tunnels {
        // retry a few times: after a reconnect the previous connection's
        // listeners may still hold the port on the server
        let mut registered = false;
        for attempt in 0..5 {
            tun.send_register_reverse(&rp.listen, &rp.target).await?;
            match tun.read_control_reply().await? {
                ControlReply::Ok(bind) => {
                    info!(
                        "reverse proxy {} -> {}: bound on server {bind}",
                        rp.listen, rp.target
                    );
                    registered = true;
                    break;
                }
                ControlReply::Err(reason) => {
                    error!(
                        "register reverse proxy {} -> {} failed (attempt {}): {reason}",
                        rp.listen,
                        rp.target,
                        attempt + 1
                    );
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                }
            }
        }
        if !registered {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("register reverse proxy {} failed", rp.listen),
            ));
        }
    }
    Ok(())
}

// Accepts server-initiated tunnels and handles them as reverse tunnels.
async fn accept_reverse_tunnels<A>(mut acceptor: A) -> std::io::Result<()>
where
    A: AcceptTunnel,
{
    loop {
        let mut tun = acceptor.accept_tunnel().await?;

        tokio::spawn(async move {
            handle_reverse_tunnel(&mut tun)
                .await
                .inspect_err(|error| {
                    error!("reverse tunnel error: {error}");
                })
                .ok();
        });
    }
}

// Handles a reverse tunnel opened by the server: the server sends the
// client-side target to connect to, the client connects and responds with its
// bind addr, then data is copied bidirectionally.
pub async fn handle_reverse_tunnel<S, R>(tun: &mut Tunnel<S, R>) -> std::io::Result<()>
where
    S: AsyncWrite + Send + Unpin,
    R: AsyncRead + Send + Unpin,
{
    if tun.read_u8().await? != TYPE_TCP_REV {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "expected reverse tunnel",
        ));
    }

    let target = tun.read_str8().await?;
    let mut stream = TcpStream::connect(&target).await?;

    tun.response(stream.local_addr()?).await?;

    copy_bidirectional(tun, &mut stream).await?;
    Ok(())
}
