#[macro_use]
extern crate log;
extern crate async_std;
extern crate chrono;
extern crate crc;
extern crate crossbeam_utils;
extern crate crypto;
extern crate futures;
extern crate futures_timer;
extern crate rand;

pub mod client;
pub mod cryptor;
pub mod logger;
pub mod proxy;
pub mod server;
pub mod timer;
pub mod ucp;

mod util {
    use futures::channel::mpsc::{channel, Receiver, Sender};
    use futures::stream::SelectAll;
    use std::vec::Vec;

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
}

mod protocol {
    use std::vec::Vec;

    pub const VERIFY_DATA: [u8; 8] = [0xF0u8, 0xEF, 0xE, 0x2, 0xAE, 0xBC, 0x8C, 0x78];
    pub const HEARTBEAT_INTERVAL_MS: u64 = 5000;
    pub const ALIVE_TIMEOUT_TIME_MS: u128 = 60000;

    pub mod cs {
        pub const OPEN_PORT: u8 = 1;
        pub const CLOSE_PORT: u8 = 2;
        pub const SHUTDOWN_WRITE: u8 = 4;
        pub const CONNECT: u8 = 5;
        pub const CONNECT_DOMAIN_NAME: u8 = 6;
        pub const DATA: u8 = 7;
        pub const HEARTBEAT: u8 = 8;
    }

    pub mod sc {
        pub const CLOSE_PORT: u8 = 1;
        pub const SHUTDOWN_WRITE: u8 = 3;
        pub const CONNECT_OK: u8 = 4;
        pub const DATA: u8 = 5;
        pub const HEARTBEAT_RSP: u8 = 6;
    }

    fn write_cmd_id_len(buf: &mut [u8], cmd: u8, id: u32, len: u32) {
        buf[0] = cmd;
        unsafe {
            *(buf.as_ptr().offset(1) as *mut u32) = id.to_be();
            *(buf.as_ptr().offset(5) as *mut u32) = len.to_be();
        }
    }

    fn pack_cmd_id_msg(cmd: u8, id: u32) -> [u8; 5] {
        let mut buf = [0u8; 5];
        buf[0] = cmd;
        unsafe {
            *(buf.as_ptr().offset(1) as *mut u32) = id.to_be();
        }
        buf
    }

    fn pack_cmd_id_data_msg(cmd: u8, id: u32, data: &[u8]) -> Vec<u8> {
        let mut buf = vec![0; 9 + data.len()];
        let len = data.len() as u32;

        write_cmd_id_len(&mut buf, cmd, id, len);
        buf[9..].copy_from_slice(data);

        buf
    }

    pub fn pack_cs_open_port_msg(id: u32) -> [u8; 5] {
        pack_cmd_id_msg(cs::OPEN_PORT, id)
    }

    pub fn pack_cs_connect_msg(id: u32, data: &[u8]) -> Vec<u8> {
        pack_cmd_id_data_msg(cs::CONNECT, id, data)
    }

    pub fn pack_cs_connect_domain_msg(id: u32, domain: &[u8], port: u16) -> Vec<u8> {
        let buf_len = 11 + domain.len();
        let mut buf = vec![0; buf_len];
        let len = domain.len() as u32 + 2;

        write_cmd_id_len(&mut buf, cs::CONNECT_DOMAIN_NAME, id, len);
        buf[9..buf_len - 2].copy_from_slice(domain);

        unsafe {
            let offset = (buf_len - 2) as isize;
            *(buf.as_ptr().offset(offset) as *mut u16) = port.to_be();
        }

        buf
    }

    pub fn pack_cs_shutdown_write_msg(id: u32) -> [u8; 5] {
        pack_cmd_id_msg(cs::SHUTDOWN_WRITE, id)
    }

    pub fn pack_cs_data_msg(id: u32, data: &[u8]) -> Vec<u8> {
        pack_cmd_id_data_msg(cs::DATA, id, data)
    }

    pub fn pack_cs_close_port_msg(id: u32) -> [u8; 5] {
        pack_cmd_id_msg(cs::CLOSE_PORT, id)
    }

    pub fn pack_cs_heartbeat_msg() -> [u8; 1] {
        let buf = [cs::HEARTBEAT];
        buf
    }

    pub fn pack_sc_close_port_msg(id: u32) -> [u8; 5] {
        pack_cmd_id_msg(sc::CLOSE_PORT, id)
    }

    pub fn pack_sc_shutdown_write_msg(id: u32) -> [u8; 5] {
        pack_cmd_id_msg(sc::SHUTDOWN_WRITE, id)
    }

    pub fn pack_sc_connect_ok_msg(id: u32, data: &[u8]) -> Vec<u8> {
        pack_cmd_id_data_msg(sc::CONNECT_OK, id, data)
    }

    pub fn pack_sc_data_msg(id: u32, data: &[u8]) -> Vec<u8> {
        pack_cmd_id_data_msg(sc::DATA, id, data)
    }

    pub fn pack_sc_heartbeat_rsp_msg() -> [u8; 1] {
        let buf = [sc::HEARTBEAT_RSP];
        buf
    }
}
