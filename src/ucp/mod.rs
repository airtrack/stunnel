pub use listener::{UcpListener, UcpListenerMetrics};
pub use stream::{UcpStream, UcpStreamMetrics};

mod internal;
mod listener;
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
const HEARTBEAT_INTERVAL_MILLIS: u128 = 2500;
const UCP_STREAM_BROKEN_MILLIS: u128 = 20000;
const SKIP_RESEND_TIMES: u32 = 2;
