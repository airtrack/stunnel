use std::{future::Future, pin::Pin};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, copy_bidirectional},
    net::{TcpListener, TcpStream, UdpSocket},
};

use crate::tunnel::{
    AcceptTunnel, AsyncReadDatagramExt, AsyncWriteDatagramExt, CTRL_ACK, CTRL_ERR,
    CTRL_REGISTER_REVERSE, CTRL_REGISTER_REVERSE_END, OpenTunnel, TYPE_CONTROL, TYPE_TCP_FWD,
    TYPE_TCP_REV, TYPE_UDP_FWD, Tunnel,
};

enum Incoming<S, R> {
    Udp(Tunnel<S, R>),
    Tcp((Tunnel<S, R>, String)),
    Control(Tunnel<S, R>),
}

// Reads the tunnel type of a tunnel and classifies it into Incoming.
async fn into_incoming<S, R>(mut tun: Tunnel<S, R>) -> std::io::Result<Incoming<S, R>>
where
    S: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    match tun.read_u8().await? {
        TYPE_UDP_FWD => Ok(Incoming::Udp(tun)),
        TYPE_TCP_FWD => {
            let addr = tun.read_str8().await?;
            Ok(Incoming::Tcp((tun, addr)))
        }
        TYPE_CONTROL => Ok(Incoming::Control(tun)),
        typ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid tunnel type: {typ}"),
        )),
    }
}

// Handles one connection: accepts tunnels and spawns a task per tunnel, so
// reading the tunnel type of one tunnel never blocks accepting the others.
// The control tunnel task owns the reverse listeners of the connection: they
// are joined with the control tunnel and end when it dies, and the control
// tunnel is finished so the client reconnects and re-registers.
pub async fn handle_all_kinds_tunnels<O, A>(opener: O, mut acceptor: A) -> std::io::Result<()>
where
    O: OpenTunnel,
    A: AcceptTunnel,
{
    loop {
        let tun = acceptor.accept_tunnel().await?;

        let opener = opener.clone();

        tokio::spawn(async move {
            match into_incoming(tun).await {
                Ok(Incoming::Control(tun)) => {
                    // the control tunnel is the liveness signal of the
                    // connection: when it dies, the joined reverse listeners
                    // end with it, and the tunnel is finished so the client
                    // reconnects and re-registers
                    handle_control_tunnel(tun, opener)
                        .await
                        .inspect_err(|error| {
                            log::error!("control tunnel error: {error}");
                        })
                        .ok();
                }
                Ok(Incoming::Udp(tun)) => {
                    handle_udp_tunnel(tun)
                        .await
                        .inspect_err(|error| {
                            log::error!("handle udp tunnel error: {error}");
                        })
                        .ok();
                }
                Ok(Incoming::Tcp((tun, destination))) => {
                    handle_tcp_tunnel(tun, destination)
                        .await
                        .inspect_err(|error| {
                            log::error!("handle tcp tunnel error: {error}");
                        })
                        .ok();
                }
                Err(error) => {
                    log::error!("accept tunnel error: {error}");
                }
            }
        });
    }
}

// Dispatches a forward tunnel: TCP/UDP tunnels are handled here, a control
// tunnel is a protocol error.
pub async fn handle_forward_tunnel<S, R>(send: S, recv: R) -> std::io::Result<(u64, u64)>
where
    S: AsyncWrite + Send + Unpin,
    R: AsyncRead + Send + Unpin,
{
    match into_incoming(Tunnel::new(send, recv)).await? {
        Incoming::Udp(tun) => handle_udp_tunnel(tun).await,
        Incoming::Tcp((tun, destination)) => handle_tcp_tunnel(tun, destination).await,
        Incoming::Control(_) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unexpected control tunnel",
        )),
    }
}

async fn handle_tcp_tunnel<S, R>(
    mut tun: Tunnel<S, R>,
    destination: String,
) -> std::io::Result<(u64, u64)>
where
    S: AsyncWrite + Send + Unpin,
    R: AsyncRead + Send + Unpin,
{
    let mut stream = TcpStream::connect(destination).await?;
    tun.response(stream.local_addr()?).await?;
    copy_bidirectional(&mut tun, &mut stream).await
}

async fn handle_udp_tunnel<S, R>(mut tun: Tunnel<S, R>) -> std::io::Result<(u64, u64)>
where
    S: AsyncWrite + Send + Unpin,
    R: AsyncRead + Send + Unpin,
{
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    tun.response(socket.local_addr()?).await?;
    copy_bidirectional_udp_socket(tun, &socket).await
}

async fn copy_bidirectional_udp_socket<S, R>(
    tun: Tunnel<S, R>,
    socket: &UdpSocket,
) -> std::io::Result<(u64, u64)>
where
    S: AsyncWrite + Send + Unpin,
    R: AsyncRead + Send + Unpin,
{
    async fn r<S>(socket: &UdpSocket, send: &mut S) -> std::io::Result<()>
    where
        S: AsyncWrite + Send + Unpin,
    {
        let mut buf = [0u8; 1500];
        loop {
            let (n, from) = socket.recv_from(&mut buf).await?;
            send.send_datagram(&buf[..n], from).await?;
        }
    }

    async fn w<R>(socket: &UdpSocket, recv: &mut R) -> std::io::Result<()>
    where
        R: AsyncRead + Send + Unpin,
    {
        let mut buf = [0u8; 1500];
        loop {
            let (n, target) = recv.recv_datagram(&mut buf).await?;
            socket.send_to(&buf[..n], target).await?;
        }
    }

    let (mut send, mut recv) = tun.split();
    futures::try_join!(r(socket, &mut send), w(socket, &mut recv)).map(|_| (0, 0))
}

// Accepts TCP connections on the reverse listener and sends them back to the
// client as reverse tunnels. The client connects to `target` on its side and
// responds with its bind addr, then data is copied bidirectionally.
async fn handle_reverse_tunnels<O>(
    listener: TcpListener,
    target: String,
    opener: O,
) -> std::io::Result<()>
where
    O: OpenTunnel,
{
    loop {
        let (mut stream, _) = listener.accept().await?;

        let mut opener = opener.clone();
        let target = target.clone();

        tokio::spawn(async move {
            let result = async {
                let mut tun = opener.open_tunnel().await?;

                tun.write_u8(TYPE_TCP_REV).await?;
                tun.write_str8(&target).await?;

                // client connects to its local target and responds with its bind addr
                tun.read_str8().await?;

                copy_bidirectional(&mut tun, &mut stream).await?;
                Ok::<(), std::io::Error>(())
            }
            .await;

            if let Err(error) = result {
                log::error!("reverse tunnel to {target} error: {error}");
            }
        });
    }
}

// Handles the control tunnel of a connection. Reads reverse proxy
// registrations and binds their listeners until the client signals the end of
// registration, then holds the control tunnel together with the listeners so
// they all end when any of them fails, typically the control tunnel dying.
// Dropping the tunnel finishes its stream so the client reconnects and
// re-registers.
async fn handle_control_tunnel<S, R, O>(mut tun: Tunnel<S, R>, opener: O) -> std::io::Result<()>
where
    S: AsyncWrite + Send + Unpin,
    R: AsyncRead + Send + Unpin,
    O: OpenTunnel,
{
    let mut listeners = Vec::new();
    loop {
        match tun.read_u8().await? {
            CTRL_REGISTER_REVERSE => {
                let listen = tun.read_str8().await?;
                let target = tun.read_str8().await?;

                match TcpListener::bind(&listen).await {
                    Ok(listener) => {
                        let bind = listener.local_addr()?.to_string();
                        log::info!("reverse listener {listen} -> {target} bound: {bind}");
                        listeners.push((listener, target));

                        tun.write_u8(CTRL_ACK).await?;
                        tun.write_str8(&bind).await?;
                    }
                    Err(error) => {
                        let reason = error.to_string();
                        tun.write_u8(CTRL_ERR).await?;
                        tun.write_str8(&reason).await?;
                        log::error!("bind reverse listener {listen} failed: {reason}");
                    }
                }
            }
            CTRL_REGISTER_REVERSE_END => break,
            typ => {
                let reason = format!("unknown control message: {typ}");
                tun.write_u8(CTRL_ERR).await?;
                tun.write_str8(&reason).await?;
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, reason));
            }
        }
    }

    // registration done: the control tunnel becomes the holder of the
    // connection, run it together with the reverse listeners
    let mut futs: Vec<Pin<Box<dyn Future<Output = std::io::Result<()>> + Send>>> = Vec::new();
    for (listener, target) in listeners {
        futs.push(Box::pin(handle_reverse_tunnels(
            listener,
            target,
            opener.clone(),
        )));
    }
    futs.push(Box::pin(hold_control_tunnel(tun)));

    futures::future::try_join_all(futs).await.map(|_| ())
}

// Holds the control tunnel open after registration: reads until the
// connection dies, ending the joined reverse listeners with it. A closed
// control tunnel is treated as an error so try_join_all tears everything
// down instead of waiting on the never-ending listeners.
async fn hold_control_tunnel<S, R>(mut tun: Tunnel<S, R>) -> std::io::Result<()>
where
    S: Send + Unpin,
    R: AsyncRead + Send + Unpin,
{
    let mut buf = [0u8; 64];
    loop {
        match tun.read(&mut buf).await {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "control tunnel closed",
                ));
            }
            Ok(_) => {}
            Err(error) => return Err(error),
        }
    }
}
