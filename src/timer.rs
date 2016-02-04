use std::sync::mpsc::channel;
use std::sync::mpsc::Sender;
use std::sync::mpsc::Receiver;
use std::time::Duration;
use std::thread;

pub struct Timer;

impl Timer {
    pub fn new(ms: u32) -> Receiver<()> {
        let (tx, rx) = channel();

        thread::spawn(move || {
            timer_loop(tx, ms);
        });

        rx
    }
}

fn timer_loop(tx: Sender<()>, ms: u32) {
    let t = Duration::from_millis(ms as u64);
    loop {
        thread::sleep(t);
        match tx.send(()) {
            Ok(_) => {},
            Err(_) => break
        }
    }
}
