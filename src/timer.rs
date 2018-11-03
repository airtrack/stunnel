use std::time::Duration;
use std::thread;

use crossbeam_channel::select;
use crossbeam_channel::{Sender, Receiver};
use crossbeam_channel as channel;

pub struct Timer;

impl Timer {
    pub fn new(ms: u32) -> Receiver<()> {
        let (tx, rx) = channel::bounded(10);

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
        select! {
            send(tx, ()) => {},
            default => break
        }
    }
}
