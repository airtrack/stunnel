use std::io::Write;
use std::vec::Vec;

use async_std::{stream::StreamExt, task};
use chrono::prelude::*;
use futures::channel::mpsc::{unbounded, UnboundedReceiver, UnboundedSender};
use log::{self, Level, LevelFilter, Metadata, Record, SetLoggerError};

use crate::util::FileRotate;

struct ChannelLogger {
    level: Level,
    sender: UnboundedSender<Vec<u8>>,
}

impl log::Log for ChannelLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= self.level
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let mut msg = Vec::new();
            let datetime = Local::now();

            let _ = write!(
                &mut msg,
                "[{}][{}][{}:{}] - {}\n",
                datetime.format("%F %T%.6f").to_string(),
                record.level(),
                record.file().unwrap(),
                record.line().unwrap(),
                record.args()
            );

            let _ = self.sender.unbounded_send(msg);
        }
    }

    fn flush(&self) {}
}

impl ChannelLogger {
    async fn run(
        mut receiver: UnboundedReceiver<Vec<u8>>,
        path: String,
        rotate_count: usize,
        rotate_size: usize,
    ) {
        let mut file = FileRotate::open(path, rotate_size, rotate_count, None).await;
        loop {
            match receiver.next().await {
                Some(msg) => {
                    file.write_all(&msg).await;
                }
                None => {
                    break;
                }
            }
        }
    }
}

pub fn init(
    level: Level,
    log_path: String,
    rotate_count: usize,
    rotate_size: usize,
) -> Result<(), SetLoggerError> {
    let (sender, receiver) = unbounded();

    task::spawn(async move {
        ChannelLogger::run(receiver, log_path, rotate_count, rotate_size).await;
    });

    log::set_max_level(LevelFilter::Info);
    log::set_boxed_logger(Box::new(ChannelLogger { level, sender }))
}
