pub use protocol::{UdpDataPacker, UdpDataUnpacker};

pub mod client;
pub mod server;

mod cryptor;
mod interval;
mod protocol;
mod util;

pub fn cipher_key_size() -> (usize, usize) {
    cryptor::Cryptor::key_size_range()
}
