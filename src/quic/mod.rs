pub mod quinn;
pub mod s2n_quic;

pub struct Config {
    pub addr: String,
    pub cert: String,
    pub priv_key: String,
    pub loss_threshold: u32,
}
