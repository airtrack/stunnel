use std::vec::Vec;
use std::collections::vec_deque::VecDeque;
use std::sync::{Arc, Mutex, Condvar};
use std::fs::OpenOptions;
use std::io::Write;
use std::thread;
use log;
use log::{LogRecord, LogLevel, LogMetadata, SetLoggerError};

struct ChannelLogger {
    level: LogLevel,
    msg_queue: Arc<(Mutex<VecDeque<Vec<u8>>>, Condvar)>
}

impl log::Log for ChannelLogger {
    fn enabled(&self, metadata: &LogMetadata) -> bool {
        metadata.level() <= self.level
    }

    fn log(&self, record: &LogRecord) {
        if self.enabled(record.metadata()) {
            let mut data = Vec::new();
            let _ = write!(&mut data, "{} - {}\n",
                           record.level(), record.args());

            let &(ref lock, ref cvar) = &*self.msg_queue;
            let mut queue = lock.lock().unwrap();
            queue.push_back(data);
            cvar.notify_one();
        }
    }
}

fn log_thread_func(msg_queue: Arc<(Mutex<VecDeque<Vec<u8>>>, Condvar)>,
                   log_path: String) {
    loop {
        let &(ref lock, ref cvar) = &*msg_queue;
        let mut queue = lock.lock().unwrap();
        while queue.is_empty() {
            queue = cvar.wait(queue).unwrap();
        }

        let data = queue.pop_front().unwrap();
        if !log_path.is_empty() {
            let file = OpenOptions::new().create(true).
                write(true).append(true).open(&log_path);
            match file {
                Ok(mut f) => { let _ = f.write_all(&data); },
                Err(_) => { }
            }
        }
    }
}

pub fn init(level: LogLevel, log_path: String) -> Result<(), SetLoggerError> {
    let sender = Arc::new((Mutex::new(VecDeque::new()), Condvar::new()));
    let receiver = sender.clone();

    thread::spawn(move || {
        log_thread_func(receiver, log_path);
    });

    log::set_logger(|max_log_level| {
        max_log_level.set(log::LogLevelFilter::Info);
        Box::new(ChannelLogger { level: level, msg_queue: sender })
    })
}
