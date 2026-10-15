-- Grafana SQL for the metrics stunnel reports over OTLP.
--
-- Schema: the OpenTelemetry collector's clickhouseexporter tables, in database
-- `otel` -- otel_metrics_sum (counters, column Value), otel_metrics_histogram
-- (Count / Sum / BucketCounts / ExplicitBounds), otel_metrics_gauge (Value).
-- Labels live in the Attributes map: Attributes['direction'], and a key a series
-- does not carry reads as ''. ddl: collector clickhouseexporter internal/sqltemplates.
--
-- Two services are queried: `stunnel-client`, which owns the proxy listeners,
-- and `stunnel-server`, which forwards the tunnels to the outbound targets.
-- A panel that only one end reports carries that end's name. A panel both ends
-- report filters on both and keeps ServiceName as a series label. The generated
-- dashboard turns the two names into its Client and Server variables, so a
-- renamed service_name is picked up there.
--
-- Macros are the ClickHouse plugin's: $__timeFilter(time) expands to the
-- panel's range, $__timeInterval(TimeUnix) to its bucket.
--
-- Every counter is CUMULATIVE -- stunnel exports with Temporality::Cumulative,
-- once every otel.export_interval_secs (15 by default) -- so an interval's value
-- is the difference between consecutive points. That difference is taken with
-- lagInFrame over (MetricName, the whole label map, StartTimeUnix), never with
-- max-min inside a bucket: a Grafana bucket is usually one export wide, and a
-- single point has no difference to give (every panel would read 0).
-- Partitioning by MetricName as well as the labels keeps two metrics that carry
-- the same labels, and two series that differ in any label, from being
-- differenced against each other. Partitioning by StartTimeUnix keeps a
-- restart's counters, which start over at zero, out of their predecessor's
-- series.
--
-- The difference defaults to 0 for the first point of a series: a cumulative
-- counter starts at zero, so that point is itself a delta (everything the
-- counter saw before its first export). Without that default a rare series --
-- one failed transport connect, one reverse registration -- would be swallowed
-- as a baseline and never drawn. That is also why the differencing subquery
-- carries NO time filter and the range is applied to the bucketed time outside
-- it: a series' first point is often older than the panel's range, and it is
-- only cheap to read because ServiceName and MetricName are the table's sorting
-- key. greatest(..., 0) absorbs anything left over from a series that is not
-- monotonic after all.
--
-- Gauges (active proxy connections, active transport connections) are levels,
-- not totals: they are read with argMax inside the bucket, never differenced.
--
-- There is no TCP payload metric to plot: a relay's byte counts only exist once
-- it ends, and a proxied connection is cut as often as it is closed. UDP is
-- counted per datagram as it is forwarded, so its panels carry both services'
-- series -- the client's SOCKS5 side against the server's tunnel side, a gap
-- between them being what the tunnel dropped.
--
-- The first section is different on purpose: its panels run a running total over
-- the whole history, so each line keeps climbing across the week you are looking
-- at. The panel's range only decides which part of that curve is drawn -- the
-- value at any point is the all-time total at that moment, not the total within
-- the range.
--
-- Each panel is one statement preceded by a header:
--   -- <title> | <view> | <unit>
-- where view is timeseries | barchart | stat and unit is a Grafana unit id.
-- docs/grafana-metrics-dashboard.json is generated from these headers.
--
-- ServiceName is a literal ('stunnel-client' or 'stunnel-server') so a statement
-- can be pasted into clickhouse-client or Explore as it stands, while the
-- generated dashboard reads the same statements with its ${client} and
-- ${server} variables.



-- == Totals (cumulative, since the first export) ==

-- Proxy connections, total | timeseries | short
SELECT time,
       pair.1 AS series,
       sum(pair.2) OVER (PARTITION BY pair.1 ORDER BY time) AS connections
FROM (
    SELECT $__timeInterval(TimeUnix) AS time,
           [('http', sumIf(delta, Attributes['protocol'] = 'http')),
            ('socks5', sumIf(delta, Attributes['protocol'] = 'socks5'))] AS pairs
    FROM (
        SELECT TimeUnix,
               Attributes,
               StartTimeUnix,
               greatest(Value - lagInFrame(Value, 1, 0)
                        OVER (PARTITION BY MetricName, toString(Attributes), StartTimeUnix
                              ORDER BY TimeUnix), 0) AS delta
        FROM otel.otel_metrics_sum
        WHERE MetricName = 'stunnel.proxy.connections'
          AND ServiceName = 'stunnel-client'
    )
    GROUP BY time
)
ARRAY JOIN pairs AS pair
ORDER BY time;

-- UDP bytes, total | timeseries | bytes
SELECT time,
       pair.1 AS series,
       sum(pair.2) OVER (PARTITION BY pair.1 ORDER BY time) AS bytes
FROM (
    SELECT $__timeInterval(TimeUnix) AS time,
           [(concat(ServiceName, ' up'), sumIf(delta, Attributes['direction'] = 'up')),
            (concat(ServiceName, ' down'), sumIf(delta, Attributes['direction'] = 'down'))] AS pairs
    FROM (
        SELECT TimeUnix,
               ServiceName,
               Attributes,
               StartTimeUnix,
               greatest(Value - lagInFrame(Value, 1, 0)
                        OVER (PARTITION BY MetricName, toString(Attributes), StartTimeUnix
                              ORDER BY TimeUnix), 0) AS delta
        FROM otel.otel_metrics_sum
        WHERE MetricName = 'stunnel.udp.bytes'
          AND ServiceName IN ('stunnel-client', 'stunnel-server')
    )
    GROUP BY time, ServiceName
)
ARRAY JOIN pairs AS pair
ORDER BY time;


-- == Proxy listeners (client) ==

-- Connections by protocol | barchart | short
SELECT time,
       protocol,
       sum(delta) AS connections
FROM (
    SELECT $__timeInterval(TimeUnix) AS time,
           Attributes['protocol'] AS protocol,
           greatest(Value - lagInFrame(Value, 1, 0)
                    OVER (PARTITION BY MetricName, toString(Attributes), StartTimeUnix
                          ORDER BY TimeUnix), 0) AS delta
    FROM otel.otel_metrics_sum
    WHERE MetricName = 'stunnel.proxy.connections'
      AND ServiceName = 'stunnel-client'
)
WHERE $__timeFilter(time)
GROUP BY time, protocol
ORDER BY time;

-- Active connections | timeseries | short
SELECT $__timeInterval(TimeUnix) AS time,
       Attributes['protocol'] AS protocol,
       argMax(Value, TimeUnix) AS active
FROM otel.otel_metrics_gauge
WHERE MetricName = 'stunnel.proxy.active_connections'
  AND ServiceName = 'stunnel-client'
  AND $__timeFilter(TimeUnix)
GROUP BY time, protocol
ORDER BY time;

-- Connection duration p95 | timeseries | s
SELECT time,
       series,
       if(arraySum(counts) = 0, NULL,
          arrayElement(bounds,
                       least(arrayCount(x -> x < 0.95 * arraySum(counts),
                                        arrayCumSum(counts)) + 1,
                             length(bounds)))) AS p95
FROM (
    SELECT time,
           series,
           bounds,
           arrayMap((hi, lo) -> greatest(toInt64(hi) - toInt64(lo), 0),
                    last_counts,
                    lagInFrame(last_counts, 1, arrayMap(x -> toUInt64(0), last_counts))
                        OVER (PARTITION BY series ORDER BY time)) AS counts
    FROM (
        SELECT $__timeInterval(TimeUnix) AS time,
               Attributes['protocol'] AS series,
               argMax(BucketCounts, TimeUnix) AS last_counts,
               any(ExplicitBounds) AS bounds
        FROM otel.otel_metrics_histogram
        WHERE MetricName = 'stunnel.proxy.connection.duration'
          AND ServiceName = 'stunnel-client'
        GROUP BY time, series
    )
)
WHERE $__timeFilter(time)
ORDER BY time;


-- == UDP ==

-- UDP packets by direction | timeseries | short
SELECT time,
       concat(ServiceName, ' ', direction) AS series,
       sum(delta) AS packets
FROM (
    SELECT $__timeInterval(TimeUnix) AS time,
           ServiceName,
           Attributes['direction'] AS direction,
           greatest(Value - lagInFrame(Value, 1, 0)
                    OVER (PARTITION BY MetricName, toString(Attributes), StartTimeUnix
                          ORDER BY TimeUnix), 0) AS delta
    FROM otel.otel_metrics_sum
    WHERE MetricName = 'stunnel.udp.packets'
      AND ServiceName IN ('stunnel-client', 'stunnel-server')
)
WHERE $__timeFilter(time)
GROUP BY time, series
ORDER BY time;

-- UDP bytes by direction | timeseries | bytes
SELECT time,
       concat(ServiceName, ' ', direction) AS series,
       sum(delta) AS bytes
FROM (
    SELECT $__timeInterval(TimeUnix) AS time,
           ServiceName,
           Attributes['direction'] AS direction,
           greatest(Value - lagInFrame(Value, 1, 0)
                    OVER (PARTITION BY MetricName, toString(Attributes), StartTimeUnix
                          ORDER BY TimeUnix), 0) AS delta
    FROM otel.otel_metrics_sum
    WHERE MetricName = 'stunnel.udp.bytes'
      AND ServiceName IN ('stunnel-client', 'stunnel-server')
)
WHERE $__timeFilter(time)
GROUP BY time, series
ORDER BY time;


-- == Transport ==

-- Transport connections by transport | barchart | short
SELECT time,
       service,
       transport,
       sum(delta) AS connections
FROM (
    SELECT $__timeInterval(TimeUnix) AS time,
           ServiceName AS service,
           Attributes['transport'] AS transport,
           greatest(Value - lagInFrame(Value, 1, 0)
                    OVER (PARTITION BY MetricName, toString(Attributes), StartTimeUnix
                          ORDER BY TimeUnix), 0) AS delta
    FROM otel.otel_metrics_sum
    WHERE MetricName = 'stunnel.transport.connections'
      AND ServiceName IN ('stunnel-client', 'stunnel-server')
)
WHERE $__timeFilter(time)
GROUP BY time, service, transport
ORDER BY time;

-- Failed transport connections | timeseries | short
SELECT time,
       service,
       transport,
       sum(delta) AS failed
FROM (
    SELECT $__timeInterval(TimeUnix) AS time,
           ServiceName AS service,
           Attributes['transport'] AS transport,
           greatest(Value - lagInFrame(Value, 1, 0)
                    OVER (PARTITION BY MetricName, toString(Attributes), StartTimeUnix
                          ORDER BY TimeUnix), 0) AS delta
    FROM otel.otel_metrics_sum
    WHERE MetricName = 'stunnel.transport.connections'
      AND Attributes['outcome'] = 'error'
      AND ServiceName IN ('stunnel-client', 'stunnel-server')
)
WHERE $__timeFilter(time)
GROUP BY time, service, transport
ORDER BY time;

-- Active transport connections | timeseries | short
SELECT $__timeInterval(TimeUnix) AS time,
       ServiceName AS service,
       Attributes['transport'] AS transport,
       argMax(Value, TimeUnix) AS active
FROM otel.otel_metrics_gauge
WHERE MetricName = 'stunnel.transport.active_connections'
  AND ServiceName IN ('stunnel-client', 'stunnel-server')
  AND $__timeFilter(TimeUnix)
GROUP BY time, service, transport
ORDER BY time;

-- Transport connection duration p95 | timeseries | s
SELECT time,
       series,
       if(arraySum(counts) = 0, NULL,
          arrayElement(bounds,
                       least(arrayCount(x -> x < 0.95 * arraySum(counts),
                                        arrayCumSum(counts)) + 1,
                             length(bounds)))) AS p95
FROM (
    SELECT time,
           series,
           bounds,
           arrayMap((hi, lo) -> greatest(toInt64(hi) - toInt64(lo), 0),
                    last_counts,
                    lagInFrame(last_counts, 1, arrayMap(x -> toUInt64(0), last_counts))
                        OVER (PARTITION BY series ORDER BY time)) AS counts
    FROM (
        SELECT $__timeInterval(TimeUnix) AS time,
               concat(ServiceName, ' ', Attributes['transport']) AS series,
               argMax(BucketCounts, TimeUnix) AS last_counts,
               any(ExplicitBounds) AS bounds
        FROM otel.otel_metrics_histogram
        WHERE MetricName = 'stunnel.transport.connection.duration'
          AND ServiceName IN ('stunnel-client', 'stunnel-server')
        GROUP BY time, series
    )
)
WHERE $__timeFilter(time)
ORDER BY time;


-- == Reverse proxy ==

-- Reverse registrations by outcome | barchart | short
SELECT time,
       service,
       outcome,
       sum(delta) AS registrations
FROM (
    SELECT $__timeInterval(TimeUnix) AS time,
           ServiceName AS service,
           Attributes['outcome'] AS outcome,
           greatest(Value - lagInFrame(Value, 1, 0)
                    OVER (PARTITION BY MetricName, toString(Attributes), StartTimeUnix
                          ORDER BY TimeUnix), 0) AS delta
    FROM otel.otel_metrics_sum
    WHERE MetricName = 'stunnel.reverse.registrations'
      AND ServiceName IN ('stunnel-client', 'stunnel-server')
)
WHERE $__timeFilter(time)
GROUP BY time, service, outcome
ORDER BY time;
