use s2n_quic::provider::congestion_controller::{CongestionController, Endpoint};

pub mod client;
pub mod server;

#[derive(Clone, Copy, Debug)]
struct FixedBandwidth {
    bandwidth: u32,
    bytes_in_flight: usize,
}

#[derive(Debug)]
struct FixedBandwidthEndpoint {
    bandwidth: u32,
}

impl CongestionController for FixedBandwidth {
    type PacketInfo = ();

    fn congestion_window(&self) -> u32 {
        self.bandwidth
    }

    fn bytes_in_flight(&self) -> u32 {
        self.bytes_in_flight as u32
    }

    fn is_congestion_limited(&self) -> bool {
        false
    }

    fn requires_fast_retransmission(&self) -> bool {
        true
    }

    fn on_packet_sent<Pub: s2n_quic::provider::congestion_controller::Publisher>(
        &mut self,
        _time_sent: s2n_quic::provider::congestion_controller::Timestamp,
        sent_bytes: usize,
        _app_limited: Option<bool>,
        _rtt_estimator: &s2n_quic::provider::congestion_controller::RttEstimator,
        _publisher: &mut Pub,
    ) -> Self::PacketInfo {
        self.bytes_in_flight += sent_bytes;
    }

    fn on_rtt_update<Pub: s2n_quic::provider::congestion_controller::Publisher>(
        &mut self,
        _time_sent: s2n_quic::provider::congestion_controller::Timestamp,
        _now: s2n_quic::provider::congestion_controller::Timestamp,
        _rtt_estimator: &s2n_quic::provider::congestion_controller::RttEstimator,
        _publisher: &mut Pub,
    ) {
    }

    fn on_ack<Pub: s2n_quic::provider::congestion_controller::Publisher>(
        &mut self,
        _newest_acked_time_sent: s2n_quic::provider::congestion_controller::Timestamp,
        bytes_acknowledged: usize,
        _newest_acked_packet_info: Self::PacketInfo,
        _rtt_estimator: &s2n_quic::provider::congestion_controller::RttEstimator,
        _random_generator: &mut dyn s2n_quic_core::random::Generator,
        _ack_receive_time: s2n_quic::provider::congestion_controller::Timestamp,
        _publisher: &mut Pub,
    ) {
        self.bytes_in_flight -= bytes_acknowledged;
    }

    fn on_packet_lost<Pub: s2n_quic::provider::congestion_controller::Publisher>(
        &mut self,
        lost_bytes: u32,
        _packet_info: Self::PacketInfo,
        _persistent_congestion: bool,
        _new_loss_burst: bool,
        _random_generator: &mut dyn s2n_quic_core::random::Generator,
        _timestamp: s2n_quic::provider::congestion_controller::Timestamp,
        _publisher: &mut Pub,
    ) {
        self.bytes_in_flight -= lost_bytes as usize;
    }

    fn on_explicit_congestion<Pub: s2n_quic::provider::congestion_controller::Publisher>(
        &mut self,
        _ce_count: u64,
        _event_time: s2n_quic::provider::congestion_controller::Timestamp,
        _publisher: &mut Pub,
    ) {
    }

    fn on_mtu_update<Pub: s2n_quic::provider::congestion_controller::Publisher>(
        &mut self,
        _max_data_size: u16,
        _publisher: &mut Pub,
    ) {
    }

    fn on_packet_discarded<Pub: s2n_quic::provider::congestion_controller::Publisher>(
        &mut self,
        bytes_sent: usize,
        _publisher: &mut Pub,
    ) {
        self.bytes_in_flight -= bytes_sent;
    }

    fn earliest_departure_time(
        &self,
    ) -> Option<s2n_quic::provider::congestion_controller::Timestamp> {
        None
    }
}

impl Endpoint for FixedBandwidthEndpoint {
    type CongestionController = FixedBandwidth;

    fn new_congestion_controller(
        &mut self,
        _path_info: s2n_quic::provider::congestion_controller::PathInfo,
    ) -> Self::CongestionController {
        FixedBandwidth {
            bandwidth: self.bandwidth,
            bytes_in_flight: 0,
        }
    }
}
