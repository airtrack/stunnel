use std::{any::Any, sync::Arc, time::Instant};

use quinn::congestion::{BbrConfig, Controller, ControllerFactory};

use crate::quic::Config;

pub mod client;
pub mod server;

#[derive(Clone, Copy, Debug)]
struct FixedBandwidth {
    bandwidth: u64,
}

impl Controller for FixedBandwidth {
    fn window(&self) -> u64 {
        self.bandwidth
    }

    fn initial_window(&self) -> u64 {
        self.bandwidth
    }

    fn on_congestion_event(
        &mut self,
        _now: Instant,
        _sent: Instant,
        _is_persistent_congestion: bool,
        _lost_bytes: u64,
    ) {
    }

    fn on_mtu_update(&mut self, _new_mtu: u16) {}

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(*self)
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

impl ControllerFactory for FixedBandwidth {
    fn build(self: Arc<Self>, _now: Instant, _current_mtu: u16) -> Box<dyn Controller> {
        Box::new(*self)
    }
}

fn cc_factory(config: &Config) -> Arc<dyn ControllerFactory + Send + Sync> {
    match config.cc.as_str() {
        "fixed" => Arc::new(FixedBandwidth {
            bandwidth: config.fixed_bandwidth as u64,
        }),
        _ => Arc::new(BbrConfig::default()),
    }
}
