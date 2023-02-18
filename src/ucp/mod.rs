pub use listener::UcpListener;
pub use metrics::{CsvMetricsService, MetricsService};
pub use stream::UcpStream;

use std::time::Duration;

mod internal;
mod listener;
mod metrics;
mod packet;
mod stream;

const CMD_SYN: u8 = 128;
const CMD_SYN_ACK: u8 = 129;
const CMD_ACK: u8 = 130;
const CMD_DATA: u8 = 131;
const CMD_HEARTBEAT: u8 = 132;
const CMD_HEARTBEAT_ACK: u8 = 133;
const UCP_PACKET_META_SIZE: usize = 29;
const DEFAULT_WINDOW: u32 = 512;
const DEFAULT_RTO: u32 = 100;
const SKIP_RESEND_TIMES: u32 = 2;
const BANDWIDTH: u32 = 3 * 1024 * 1024;

const STREAM_BROKEN_DURATION: Duration = Duration::from_millis(20000);
const HEARTBEAT_INTERVAL: Duration = Duration::from_millis(2500);
const METRICS_INTERVAL: Duration = Duration::from_millis(1000);
const CONGESTION_INTERVAL: Duration = Duration::from_millis(1000);
const PACING_INTERVAL: Duration = Duration::from_micros(1000);
