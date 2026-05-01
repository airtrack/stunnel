use s2n_quic::provider::{
    congestion_controller::{CongestionController, Endpoint},
    event::{ConnectionInfo, ConnectionMeta, Subscriber, events},
};

pub mod client;
pub mod server;

#[derive(Clone, Copy, Debug)]
struct S2nEventLogger {
    role: &'static str,
}

#[derive(Debug, Default)]
struct S2nEventContext {
    packets_sent: u64,
    packets_received: u64,
    tx_stream_bytes: u64,
    rx_stream_bytes: u64,
    stream_frames_sent: u64,
    stream_frames_received: u64,
    blocked_frames_sent: u64,
    blocked_frames_received: u64,
    max_credit_frames_sent: u64,
    max_credit_frames_received: u64,
    keep_alive_expired: u64,
}

impl S2nEventLogger {
    fn new(role: &'static str) -> Self {
        Self { role }
    }
}

impl Subscriber for S2nEventLogger {
    type ConnectionContext = S2nEventContext;

    fn create_connection_context(
        &mut self,
        meta: &ConnectionMeta,
        _info: &ConnectionInfo,
    ) -> Self::ConnectionContext {
        log::info!(
            "s2n-quic {} connection started: conn={:?} endpoint={:?}",
            self.role,
            meta.id,
            meta.endpoint_type
        );
        S2nEventContext::default()
    }

    fn on_packet_sent(
        &mut self,
        context: &mut Self::ConnectionContext,
        _meta: &ConnectionMeta,
        _event: &events::PacketSent,
    ) {
        context.packets_sent += 1;
    }

    fn on_packet_received(
        &mut self,
        context: &mut Self::ConnectionContext,
        _meta: &ConnectionMeta,
        _event: &events::PacketReceived,
    ) {
        context.packets_received += 1;
    }

    fn on_frame_sent(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &ConnectionMeta,
        event: &events::FrameSent,
    ) {
        observe_frame(self.role, "sent", context, meta, &event.frame);
    }

    fn on_frame_received(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &ConnectionMeta,
        event: &events::FrameReceived<'_>,
    ) {
        observe_frame(self.role, "received", context, meta, &event.frame);
    }

    fn on_rx_stream_progress(
        &mut self,
        context: &mut Self::ConnectionContext,
        _meta: &ConnectionMeta,
        event: &events::RxStreamProgress,
    ) {
        context.rx_stream_bytes += event.bytes as u64;
    }

    fn on_tx_stream_progress(
        &mut self,
        context: &mut Self::ConnectionContext,
        _meta: &ConnectionMeta,
        event: &events::TxStreamProgress,
    ) {
        context.tx_stream_bytes += event.bytes as u64;
    }

    fn on_keep_alive_timer_expired(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &ConnectionMeta,
        event: &events::KeepAliveTimerExpired,
    ) {
        context.keep_alive_expired += 1;
        let _ = meta;
        let _ = event;
    }

    fn on_connection_closed(
        &mut self,
        context: &mut Self::ConnectionContext,
        meta: &ConnectionMeta,
        event: &events::ConnectionClosed,
    ) {
        log::warn!(
            "s2n-quic {} connection closed: conn={:?} endpoint={:?} error={:?} packets_sent={} packets_received={} tx_stream_bytes={} rx_stream_bytes={} stream_frames_sent={} stream_frames_received={} blocked_sent={} blocked_received={}",
            self.role,
            meta.id,
            meta.endpoint_type,
            event.error,
            context.packets_sent,
            context.packets_received,
            context.tx_stream_bytes,
            context.rx_stream_bytes,
            context.stream_frames_sent,
            context.stream_frames_received,
            context.blocked_frames_sent,
            context.blocked_frames_received,
        );
    }
}

fn observe_frame(
    role: &'static str,
    direction: &'static str,
    context: &mut S2nEventContext,
    meta: &ConnectionMeta,
    frame: &events::Frame,
) {
    match frame {
        events::Frame::Stream { len, .. } => {
            match direction {
                "sent" => context.stream_frames_sent += 1,
                _ => context.stream_frames_received += 1,
            }
            let _ = len;
        }
        events::Frame::DataBlocked { data_limit, .. } => {
            record_blocked_frame(direction, context);
            log::warn!(
                "s2n-quic {role} data blocked {direction}: conn={:?} endpoint={:?} data_limit={data_limit}",
                meta.id,
                meta.endpoint_type
            );
        }
        events::Frame::StreamDataBlocked {
            stream_id,
            stream_data_limit,
            ..
        } => {
            record_blocked_frame(direction, context);
            log::warn!(
                "s2n-quic {role} stream data blocked {direction}: conn={:?} endpoint={:?} stream_id={stream_id} stream_data_limit={stream_data_limit}",
                meta.id,
                meta.endpoint_type
            );
        }
        events::Frame::StreamsBlocked {
            stream_type,
            stream_limit,
            ..
        } => {
            record_blocked_frame(direction, context);
            log::warn!(
                "s2n-quic {role} streams blocked {direction}: conn={:?} endpoint={:?} stream_type={stream_type:?} stream_limit={stream_limit}",
                meta.id,
                meta.endpoint_type
            );
        }
        events::Frame::MaxData { value, .. } => {
            record_credit_frame(direction, context);
            log_credit_frame_if_blocked(role, direction, context, meta, "max data", *value);
        }
        events::Frame::MaxStreamData {
            stream_type,
            id,
            value,
            ..
        } => {
            record_credit_frame(direction, context);
            if has_blocked_frame(context) {
                log::info!(
                    "s2n-quic {role} max stream data {direction}: conn={:?} endpoint={:?} stream_type={stream_type:?} stream_id={id} value={value}",
                    meta.id,
                    meta.endpoint_type
                );
            }
        }
        events::Frame::MaxStreams {
            stream_type, value, ..
        } => {
            record_credit_frame(direction, context);
            if has_blocked_frame(context) {
                log::info!(
                    "s2n-quic {role} max streams {direction}: conn={:?} endpoint={:?} stream_type={stream_type:?} value={value}",
                    meta.id,
                    meta.endpoint_type
                );
            }
        }
        _ => {}
    }
}

fn record_blocked_frame(direction: &'static str, context: &mut S2nEventContext) {
    match direction {
        "sent" => context.blocked_frames_sent += 1,
        _ => context.blocked_frames_received += 1,
    }
}

fn record_credit_frame(direction: &'static str, context: &mut S2nEventContext) {
    match direction {
        "sent" => context.max_credit_frames_sent += 1,
        _ => context.max_credit_frames_received += 1,
    }
}

fn has_blocked_frame(context: &S2nEventContext) -> bool {
    context.blocked_frames_sent > 0 || context.blocked_frames_received > 0
}

fn log_credit_frame_if_blocked(
    role: &'static str,
    direction: &'static str,
    context: &S2nEventContext,
    meta: &ConnectionMeta,
    name: &'static str,
    value: u64,
) {
    if has_blocked_frame(context) {
        log::info!(
            "s2n-quic {role} {name} {direction}: conn={:?} endpoint={:?} value={value}",
            meta.id,
            meta.endpoint_type
        );
    }
}

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
