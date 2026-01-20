pub mod quinn;
pub mod s2n_quic;

pub struct Config {
    pub addr: String,
    pub cert: String,
    pub priv_key: String,
    pub cc: String,
    pub loss_threshold: u32,
    pub fixed_bandwidth: u32,
}
