use std::{net::SocketAddr, path::PathBuf};

use serde::Deserialize;

pub mod quinn;
pub mod s2n_quic;

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
pub enum CongestionControl {
    #[serde(rename = "bbr")]
    #[default]
    Bbr,
    #[serde(rename = "fixed")]
    Fixed,
}

#[derive(Debug, Clone, Deserialize)]
pub struct QuicConfig {
    #[serde(default)]
    pub cc: CongestionControl,
    #[serde(default = "default_loss_threshold")]
    pub loss_threshold: u32,
    #[serde(default = "default_fixed_bandwidth")]
    pub fixed_bandwidth: u32,
}

impl Default for QuicConfig {
    fn default() -> Self {
        Self {
            cc: CongestionControl::default(),
            loss_threshold: default_loss_threshold(),
            fixed_bandwidth: default_fixed_bandwidth(),
        }
    }
}

pub struct Config {
    pub addr: SocketAddr,
    pub cert: PathBuf,
    pub priv_key: PathBuf,
    pub transport: QuicConfig,
}

fn default_loss_threshold() -> u32 {
    20
}

fn default_fixed_bandwidth() -> u32 {
    6 * 1024 * 1024
}
