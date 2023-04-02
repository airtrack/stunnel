use std::vec::Vec;

use futures::channel::mpsc::{channel, Receiver, Sender};
use futures::stream::SelectAll;

pub type Receivers<T> = SelectAll<Receiver<T>>;
pub type MainSender<T> = Sender<T>;
pub struct SubSenders<T>(Vec<Sender<T>>, usize);

impl<T> SubSenders<T> {
    pub fn get_one_sender(&mut self) -> Sender<T> {
        let index = self.1;
        self.1 += 1;

        if self.1 >= self.0.len() {
            self.1 = 0;
        }

        self.0.get(index).unwrap().clone()
    }
}

pub fn channel_bus<T>(
    bus_num: usize,
    buffer: usize,
) -> (MainSender<T>, SubSenders<T>, Receivers<T>) {
    let (main_sender, main_receiver) = channel(buffer);
    let mut receivers = Receivers::new();
    let mut sub_senders = SubSenders(Vec::new(), 0);

    receivers.push(main_receiver);
    for _ in 0..bus_num {
        let (sender, receiver) = channel(buffer);
        sub_senders.0.push(sender);
        receivers.push(receiver);
    }

    (main_sender, sub_senders, receivers)
}
