use async_std::task;
use async_std::{fs::File, fs::OpenOptions, io::Error, io::WriteExt};
use futures::channel::mpsc::{unbounded, UnboundedReceiver, UnboundedSender};
use futures::StreamExt;

pub struct UcpMetrics {
    pub send_queue_size: usize,
    pub recv_queue_size: usize,
    pub send_buffer_size: usize,

    pub una: u32,
    pub rto: u32,
    pub srtt: u32,
    pub rttvar: u32,
    pub rx_seq: u32,
}

impl UcpMetrics {
    fn csv_header_line() -> Vec<u8> {
        let mut data = Vec::new();
        let _ = std::io::Write::write_fmt(
            &mut data,
            format_args!(
                "{},{},{},{},{},{},{},{}\n",
                "send_queue_size",
                "recv_queue_size",
                "send_buffer_size",
                "una",
                "rto",
                "srtt",
                "rttvar",
                "rx_seq"
            ),
        );
        data
    }

    fn to_csv_line(&self) -> Vec<u8> {
        let mut data = Vec::new();
        let _ = std::io::Write::write_fmt(
            &mut data,
            format_args!(
                "{},{},{},{},{},{},{},{}\n",
                self.send_queue_size,
                self.recv_queue_size,
                self.send_buffer_size,
                self.una,
                self.rto,
                self.srtt,
                self.rttvar,
                self.rx_seq
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

struct CSVMetricsReporter {
    sender: UnboundedSender<UcpMetrics>,
}

impl MetricsReporter for CSVMetricsReporter {
    fn report_metrics(&self, metrics: UcpMetrics) {
        let _ = self.sender.unbounded_send(metrics);
    }
}

struct CSVMetricsWriter {
    path: String,
    receiver: UnboundedReceiver<UcpMetrics>,
}

impl CSVMetricsWriter {
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

pub struct CSVMetricsService {
    sender: UnboundedSender<UcpMetrics>,
}

impl MetricsService for CSVMetricsService {
    fn new_metrics_reporter(&self) -> Box<dyn MetricsReporter> {
        let sender = self.sender.clone();
        let csv_metrics_reporter = Box::new(CSVMetricsReporter { sender });
        csv_metrics_reporter
    }
}

impl CSVMetricsService {
    pub fn new(path: String) -> Self {
        let (sender, receiver) = unbounded();

        task::spawn(async move {
            let mut csv_metrics_writer = CSVMetricsWriter { path, receiver };
            csv_metrics_writer.run().await;
        });

        Self { sender }
    }
}
