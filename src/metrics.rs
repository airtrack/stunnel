//! The metric names this crate records, plus the metadata the telemetry setup
//! installs -- and nothing else. Recording happens at each call site through
//! the `metrics` macros, which resolve against the global recorder, so this
//! module holds no state and adds no layer between a call site and the facade.
//! With no recorder installed every recording is a no-op.
//!
//! [`describe_metrics`] and [`histogram_bounds`] are called once by
//! [`Telemetry::init`](crate::telemetry::Telemetry::init) at startup, before
//! anything is recorded: a recorder cannot restate a metric's description or
//! its buckets after its first use.

use metrics::{Unit, describe_counter, describe_gauge, describe_histogram};

/// Client connections served by the HTTP and SOCKS5 listeners, by `protocol`
/// (`http`, `socks5`). Counted when the connection ends, whichever way it ends:
/// a proxied connection is more often cut than closed, so an outcome label
/// would say more about the client than about the tunnel.
pub const PROXY_CONNECTIONS: &str = "stunnel.proxy.connections";
/// Time from accepting a client connection to it ending, by `protocol`.
pub const PROXY_CONNECTION_DURATION: &str = "stunnel.proxy.connection.duration";
/// Client connections currently being served, by `protocol`.
pub const PROXY_ACTIVE_CONNECTIONS: &str = "stunnel.proxy.active_connections";
/// UDP datagrams relayed, by `direction` (`up` is client to target, `down` is
/// target to client), counted by both ends as each datagram is forwarded.
pub const UDP_PACKETS: &str = "stunnel.udp.packets";
/// UDP payload bytes relayed, by `direction`, counted as each datagram is
/// forwarded. Unlike a TCP relay, a datagram is accounted for when it moves, so
/// a flow that ends abruptly loses nothing.
pub const UDP_BYTES: &str = "stunnel.udp.bytes";
/// Transport connection attempts, by `transport` (`tlstcp`, `quic`,
/// `s2n-quic`) and `outcome`: `ok` when the connection came up, `error` when the
/// connect or the handshake failed.
pub const TRANSPORT_CONNECTIONS: &str = "stunnel.transport.connections";
/// Transport connections currently up, by `transport`.
pub const TRANSPORT_ACTIVE_CONNECTIONS: &str = "stunnel.transport.active_connections";
/// How long an established transport connection lived, by `transport`.
pub const TRANSPORT_CONNECTION_DURATION: &str = "stunnel.transport.connection.duration";
/// Reverse proxy registrations by `outcome`: requested by the client, bound by
/// the server.
pub const REVERSE_REGISTRATIONS: &str = "stunnel.reverse.registrations";

/// Histogram bucket boundaries per metric, in the recorder's terms. A proxied
/// or transport connection can live for hours while a Grafana bucket is a
/// minute wide, which is why the boundaries are generous. Installed once, by
/// [`Telemetry::init`](crate::telemetry::Telemetry::init): a recorder cannot
/// restate buckets after a metric's first use.
pub fn histogram_bounds() -> Vec<(&'static str, Vec<f64>)> {
    let seconds = vec![
        0.1, 0.5, 1.0, 5.0, 15.0, 60.0, 300.0, 900.0, 3600.0, 21600.0,
    ];

    vec![
        (PROXY_CONNECTION_DURATION, seconds.clone()),
        (TRANSPORT_CONNECTION_DURATION, seconds),
    ]
}

/// Describe every metric this crate records. Must run before the first
/// recording: the recorder stores descriptions per name and never restates
/// them, so a metric described late exports without one.
pub fn describe_metrics() {
    describe_counter!(
        PROXY_CONNECTIONS,
        Unit::Count,
        "Client connections served by the proxy listeners, by protocol"
    );
    describe_histogram!(
        PROXY_CONNECTION_DURATION,
        Unit::Seconds,
        "Wall-clock duration of one client connection on a proxy listener"
    );
    describe_gauge!(
        PROXY_ACTIVE_CONNECTIONS,
        Unit::Count,
        "Client connections currently being served, by protocol"
    );
    describe_counter!(
        UDP_PACKETS,
        Unit::Count,
        "UDP datagrams relayed, by direction, counted as they are forwarded"
    );
    describe_counter!(
        UDP_BYTES,
        Unit::Bytes,
        "UDP payload bytes relayed, by direction, counted as they are forwarded"
    );
    describe_counter!(
        TRANSPORT_CONNECTIONS,
        Unit::Count,
        "Transport connection attempts, ok when the connection was established"
    );
    describe_gauge!(
        TRANSPORT_ACTIVE_CONNECTIONS,
        Unit::Count,
        "Transport connections currently up"
    );
    describe_histogram!(
        TRANSPORT_CONNECTION_DURATION,
        Unit::Seconds,
        "Wall-clock duration of one established transport connection"
    );
    describe_counter!(
        REVERSE_REGISTRATIONS,
        Unit::Count,
        "Reverse proxy registrations, requested by the client or bound by the server"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_described_metric_has_a_name_a_backend_can_read() {
        // The names are the contract with the collector and with the dashboard
        // SQL; a typo here would silently create a second series. No name
        // carries a `_total` suffix either: the exporter adds the aggregation,
        // not the name.
        let mut names = [
            PROXY_CONNECTIONS,
            PROXY_CONNECTION_DURATION,
            PROXY_ACTIVE_CONNECTIONS,
            UDP_PACKETS,
            UDP_BYTES,
            TRANSPORT_CONNECTIONS,
            TRANSPORT_ACTIVE_CONNECTIONS,
            TRANSPORT_CONNECTION_DURATION,
            REVERSE_REGISTRATIONS,
        ]
        .to_vec();
        let count = names.len();

        for name in names.iter() {
            assert!(name.starts_with("stunnel."), "{name}");
            assert!(!name.ends_with("_total"), "{name}");
        }

        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), count, "two metrics share a name");
    }

    #[test]
    fn histogram_bounds_cover_every_histogram() {
        let bounded: Vec<&str> = histogram_bounds().into_iter().map(|(n, _)| n).collect();
        for name in [PROXY_CONNECTION_DURATION, TRANSPORT_CONNECTION_DURATION] {
            assert!(bounded.contains(&name), "no bounds for {name}");
        }
        // Ascending, or the recorder's bucketing is meaningless.
        for (name, bounds) in histogram_bounds() {
            assert!(bounds.windows(2).all(|w| w[0] < w[1]), "{name}");
        }
    }
}
