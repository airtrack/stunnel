use async_std::task;
use async_std::{fs::File, fs::OpenOptions, io::Error, io::WriteExt};
use chrono::prelude::*;
use futures::channel::mpsc::{unbounded, UnboundedReceiver, UnboundedSender};
use futures::StreamExt;
use std::net::SocketAddr;

pub struct UcpMetrics {
    pub date_time: DateTime<Utc>,
    pub session_id: u32,
    pub remote_addr: SocketAddr,

    pub send_queue_size: usize,
    pub recv_queue_size: usize,
    pub send_buffer_size: usize,

    pub bandwidth: u32,
    pub send_kbps: u32,
    pub recv_kbps: u32,
    pub skip_resend_kbps: u32,

    pub una: u32,
    pub rto: u32,
    pub srtt: u32,
    pub rttvar: u32,
    pub rx_seq: u32,

    pub delay_slope: f64,
}

impl UcpMetrics {
    fn csv_header_line() -> Vec<u8> {
        let mut data = Vec::new();
        let _ = std::io::Write::write_fmt(
            &mut data,
            format_args!(
                "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
                "date_time",
                "session_id",
                "remote_addr",
                "send_queue_size",
                "recv_queue_size",
                "send_buffer_size",
                "bandwidth",
                "send_kbps",
                "recv_kbps",
                "skip_resend_kbps",
                "una",
                "rto",
                "srtt",
                "rttvar",
                "rx_seq",
                "delay_slope"
            ),
        );
        data
    }

    fn to_csv_line(&self) -> Vec<u8> {
        let mut data = Vec::new();
        let _ = std::io::Write::write_fmt(
            &mut data,
            format_args!(
                "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{:.2}\n",
                self.date_time.to_rfc3339_opts(SecondsFormat::Secs, true),
                self.session_id,
                self.remote_addr,
                self.send_queue_size,
                self.recv_queue_size,
                self.send_buffer_size,
                self.bandwidth,
                self.send_kbps,
                self.recv_kbps,
                self.skip_resend_kbps,
                self.una,
                self.rto,
                self.srtt,
                self.rttvar,
                self.rx_seq,
                self.delay_slope,
            ),
        );
        data
    }
}

pub trait MetricsReporter: Send + Sync {
    fn report_metrics(&self, metrics: UcpMetrics);
}

pub trait MetricsService: Send + Sync {
    fn new_metrics_reporter(&self) -> Box<dyn MetricsReporter>;
}

struct CsvMetricsReporter {
    sender: UnboundedSender<UcpMetrics>,
}

impl MetricsReporter for CsvMetricsReporter {
    fn report_metrics(&self, metrics: UcpMetrics) {
        let _ = self.sender.unbounded_send(metrics);
    }
}

struct CsvMetricsWriter {
    path: String,
    receiver: UnboundedReceiver<UcpMetrics>,
}

impl CsvMetricsWriter {
    async fn run(&mut self) {
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&self.path)
            .await;

        match file {
            Ok(ref mut f) => {
                let _ = f.write_all(&UcpMetrics::csv_header_line()).await;
            }
            Err(_) => {}
        }

        self.loop_recv_write(&mut file).await;
    }

    async fn loop_recv_write(&mut self, file: &mut Result<File, Error>) {
        loop {
            let metrics = self.receiver.next().await;
            if metrics.is_none() {
                break;
            }

            let metrics = metrics.unwrap();
            match file {
                Ok(ref mut f) => {
                    let _ = f.write_all(&metrics.to_csv_line()).await;
                }
                Err(_) => {}
            }
        }
    }
}

pub struct CsvMetricsService {
    sender: UnboundedSender<UcpMetrics>,
}

impl MetricsService for CsvMetricsService {
    fn new_metrics_reporter(&self) -> Box<dyn MetricsReporter> {
        let sender = self.sender.clone();
        let csv_metrics_reporter = Box::new(CsvMetricsReporter { sender });
        csv_metrics_reporter
    }
}

impl CsvMetricsService {
    pub fn new(path: String) -> Self {
        let (sender, receiver) = unbounded();

        task::spawn(async move {
            let mut csv_metrics_writer = CsvMetricsWriter { path, receiver };
            csv_metrics_writer.run().await;
        });

        Self { sender }
    }
}
