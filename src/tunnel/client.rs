use std::{future::Future, net::SocketAddr, time::Duration};

use async_trait::async_trait;
use log::{info, warn};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::tlstcp::{self, TlsReadStream, TlsWriteStream};
use crate::tunnel::Tunnel;

const TUNNEL_STAGE_WARN: Duration = Duration::from_secs(3);

#[async_trait]
pub trait IntoTunnel<S, R> {
    async fn into_tunnel(self) -> std::io::Result<Tunnel<S, R>>;
}

#[async_trait]
impl IntoTunnel<quinn::SendStream, quinn::RecvStream> for quinn::Connection {
    async fn into_tunnel(self) -> std::io::Result<Tunnel<quinn::SendStream, quinn::RecvStream>> {
        let (send, recv) = self.open_bi().await?;
        Ok(Tunnel { s: send, r: recv })
    }
}

#[async_trait]
impl IntoTunnel<s2n_quic::stream::SendStream, s2n_quic::stream::ReceiveStream>
    for s2n_quic::connection::Handle
{
    async fn into_tunnel(
        mut self,
    ) -> std::io::Result<Tunnel<s2n_quic::stream::SendStream, s2n_quic::stream::ReceiveStream>>
    {
        let conn_id = self.id();
        info!("s2n-quic client opening bidirectional stream: conn={conn_id}");
        let stream = self
            .open_bidirectional_stream()
            .await
            .inspect_err(|error| {
                warn!(
                    "s2n-quic client open bidirectional stream failed: conn={conn_id} error={error}"
                );
            })?;
        let stream_id = stream.id();
        info!("s2n-quic client bidirectional stream opened: conn={conn_id} stream={stream_id}");
        let (recv, send) = stream.split();
        Ok(Tunnel { s: send, r: recv })
    }
}

#[async_trait]
impl IntoTunnel<TlsWriteStream, TlsReadStream> for tlstcp::Connector {
    async fn into_tunnel(self) -> std::io::Result<Tunnel<TlsWriteStream, TlsReadStream>> {
        let stream = self.connect().await?;
        let (read_half, write_half) = tlstcp::split(stream);
        Ok(Tunnel {
            s: write_half,
            r: read_half,
        })
    }
}

pub async fn connect_tcp_tunnel<S, R>(
    into: impl IntoTunnel<S, R>,
    target: &str,
) -> std::io::Result<(SocketAddr, Tunnel<S, R>)>
where
    S: AsyncWrite + Send + Unpin,
    R: AsyncRead + Send + Unpin,
{
    let mut conn = tunnel_stage(target, "open tunnel stream", into.into_tunnel()).await?;

    tunnel_stage(target, "write tunnel target", async {
        conn.write_u8(target.len() as u8).await?;
        conn.write_all(target.as_bytes()).await
    })
    .await?;

    let n = tunnel_stage(target, "read tunnel response length", conn.read_u8()).await? as usize;
    let mut buf = vec![0u8; n];
    tunnel_stage(target, "read tunnel response", async {
        conn.read_exact(&mut buf)
            .await
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::Other, error))
    })
    .await?;

    if let Some(bind) = std::str::from_utf8(&buf)
        .ok()
        .and_then(|addr| addr.parse::<SocketAddr>().ok())
    {
        Ok((bind, conn))
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid addr",
        ))
    }
}

pub async fn connect_udp_tunnel<S, R>(into: impl IntoTunnel<S, R>) -> std::io::Result<Tunnel<S, R>>
where
    S: AsyncWrite + Send + Unpin,
    R: AsyncRead + Send + Unpin,
{
    let mut conn = tunnel_stage("udp", "open tunnel stream", into.into_tunnel()).await?;

    tunnel_stage("udp", "write tunnel type", conn.write_u8(0)).await?;

    let n = tunnel_stage("udp", "read tunnel response length", conn.read_u8()).await? as usize;
    let mut buf = vec![0u8; n];
    tunnel_stage("udp", "read tunnel response", async {
        conn.read_exact(&mut buf)
            .await
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::Other, error))
    })
    .await?;

    Ok(conn)
}

async fn tunnel_stage<T, F>(target: &str, stage: &'static str, future: F) -> std::io::Result<T>
where
    F: Future<Output = std::io::Result<T>>,
{
    let start = std::time::Instant::now();
    let mut warned = false;
    tokio::pin!(future);

    loop {
        if warned {
            let result = future.await;
            log_tunnel_stage_result(target, stage, start.elapsed(), &result);
            return result;
        }

        tokio::select! {
            result = &mut future => {
                log_tunnel_stage_result(target, stage, start.elapsed(), &result);
                return result;
            }
            _ = tokio::time::sleep(TUNNEL_STAGE_WARN) => {
                warned = true;
                warn!(
                    "tunnel setup waiting: target={target} stage=\"{stage}\" elapsed={:?}",
                    start.elapsed()
                );
            }
        }
    }
}

fn log_tunnel_stage_result<T>(
    target: &str,
    stage: &'static str,
    elapsed: Duration,
    result: &std::io::Result<T>,
) {
    match result {
        Ok(_) if elapsed >= TUNNEL_STAGE_WARN => {
            warn!("tunnel setup resumed: target={target} stage=\"{stage}\" elapsed={elapsed:?}");
        }
        Err(error) => {
            warn!(
                "tunnel setup failed: target={target} stage=\"{stage}\" elapsed={elapsed:?} error={error}"
            );
        }
        Ok(_) => {}
    }
}
