use std::vec::Vec;
use std::collections::vec_deque::VecDeque;
use std::sync::{Arc, Mutex, Condvar};
use std::fs::OpenOptions;
use std::io::Write;
use std::thread;
use log;
use log::{Record, Level, Metadata, SetLoggerError, LevelFilter};
use time::{at, get_time, strftime};

struct ChannelLogger {
    level: Level,
    msg_queue: Arc<(Mutex<VecDeque<Vec<u8>>>, Condvar)>
}

impl log::Log for ChannelLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= self.level
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let mut data = Vec::new();
            let now = at(get_time());
            let date = strftime("%F %T", &now).unwrap();
            let microseconds = now.tm_nsec / 1000;

            let _ = write!(&mut data, "[{}.{:06}][{}] - {}\n",
                           date, microseconds, record.level(), record.args());

            let &(ref lock, ref cvar) = &*self.msg_queue;
            let mut queue = lock.lock().unwrap();
            queue.push_back(data);
            cvar.notify_one();
        }
    }

    fn flush(&self) {
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

pub fn init(level: Level, log_path: String) -> Result<(), SetLoggerError> {
    let sender = Arc::new((Mutex::new(VecDeque::new()), Condvar::new()));
    let receiver = sender.clone();

    thread::spawn(move || {
        log_thread_func(receiver, log_path);
    });

    log::set_max_level(LevelFilter::Info);
    log::set_boxed_logger(Box::new(ChannelLogger { level: level, msg_queue: sender }))
}
