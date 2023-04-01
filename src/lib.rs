#[macro_use]
extern crate log;

pub mod client;
pub mod cryptor;
pub mod logger;
pub mod proxy;
pub mod server;
pub mod timer;
pub mod ucp;

mod util {
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

    use async_std::fs::{remove_file, rename, File, OpenOptions};
    use async_std::io::WriteExt;

    pub struct FileRotate {
        path: String,
        file: Option<File>,
        header: Option<Vec<u8>>,
        rotate_size: usize,
        rotate_count: usize,
        written_size: usize,
    }

    impl FileRotate {
        pub async fn open(
            path: String,
            rotate_size: usize,
            rotate_count: usize,
            header: Option<Vec<u8>>,
        ) -> Self {
            let mut file_rotate = Self {
                path,
                file: None,
                header,
                rotate_size,
                rotate_count,
                written_size: 0,
            };

            file_rotate.open_file().await;
            file_rotate
        }

        pub async fn write_all(&mut self, buf: &[u8]) {
            if let Some(ref mut f) = self.file {
                let _ = f.write_all(buf).await;
                // Call async_std::fs::File::flush to drain buffer in async_std::fs::File,
                // which means call std::fs::File::write_all.
                let _ = f.flush().await;
            }

            self.written_size += buf.len();
            if self.written_size >= self.rotate_size {
                self.rotate_file().await;
            }
        }

        async fn rotate_file(&mut self) {
            if self.rotate_count == 0 {
                return;
            }

            let mut file_number = self.rotate_count - 1;
            let _ = remove_file(self.generate_rotate_file_name(file_number)).await;

            while file_number > 0 {
                let to = self.generate_rotate_file_name(file_number);
                let from = self.generate_rotate_file_name(file_number - 1);
                let _ = rename(from, to).await;
                file_number -= 1;
            }

            self.open_file().await;
        }

        async fn open_file(&mut self) {
            self.written_size = 0;
            self.file = OpenOptions::new()
                .create(true)
                .write(true)
                .append(true)
                .open(&self.path)
                .await
                .ok();

            if let Some(ref file) = self.file {
                match file.metadata().await {
                    Ok(metadata) => {
                        self.written_size = metadata.len() as usize;
                    }
                    Err(_) => {}
                }
            }

            self.write_file_header().await;
        }

        async fn write_file_header(&mut self) {
            if self.header.is_none() {
                return;
            }

            if let Some(ref mut file) = self.file {
                if self.written_size == 0 {
                    let header = self.header.as_ref().unwrap();
                    let _ = file.write_all(header).await;
                    self.written_size += header.len();
                }
            }
        }

        fn generate_rotate_file_name(&self, file_number: usize) -> String {
            let mut path = self.path.clone();

            if file_number > 0 {
                path.push('.');
                path.push_str(&file_number.to_string());
            }

            path
        }
    }
}

mod protocol {
    use std::net::SocketAddr;
    use std::str::from_utf8;
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
        pub const UDP_ASSOCIATE: u8 = 9;
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

    pub fn pack_udp_associate_msg(id: u32, data: &[u8]) -> Vec<u8> {
        pack_cmd_id_data_msg(cs::UDP_ASSOCIATE, id, data)
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

    pub struct UdpDataPacker;

    impl UdpDataPacker {
        pub fn pack_udp_data(&self, data: &[u8], addr: &SocketAddr) -> Vec<u8> {
            let mut addr_buf = Vec::new();
            let _ = std::io::Write::write_fmt(&mut addr_buf, format_args!("{}", addr));

            let mut buf = vec![0; 4 + data.len()];
            let len = (data.len() + addr_buf.len()) as u16;
            let data_len = data.len() as u16;

            unsafe {
                *(buf.as_ptr() as *mut u16) = len.to_be();
                *(buf.as_ptr().offset(2) as *mut u16) = data_len.to_be();
            }

            buf[4..].copy_from_slice(data);
            buf.append(&mut addr_buf);

            buf
        }
    }

    pub struct UdpDataUnpacker {
        buffer: Vec<u8>,
    }

    impl UdpDataUnpacker {
        pub fn new() -> Self {
            Self { buffer: Vec::new() }
        }

        pub fn append_data(&mut self, mut buf: Vec<u8>) {
            self.buffer.append(&mut buf)
        }

        pub fn unpack_udp_data(&mut self) -> Option<(Vec<u8>, SocketAddr)> {
            let (len, _) = self.unpack_udp_data_length(&self.buffer)?;
            let total_len = 4 + len;

            if self.buffer.len() < total_len {
                return None;
            }

            let udp_data = self.do_unpack_udp_data(&self.buffer);
            self.buffer.drain(0..total_len);
            Some(udp_data)
        }

        fn unpack_udp_data_length(&self, buf: &[u8]) -> Option<(usize, usize)> {
            if buf.len() < 4 {
                return None;
            }

            let len = u16::from_be(unsafe { *(buf.as_ptr() as *const u16) }) as usize;
            let data_len =
                u16::from_be(unsafe { *(buf.as_ptr().offset(2) as *const u16) }) as usize;
            Some((len, data_len))
        }

        fn do_unpack_udp_data(&self, buf: &[u8]) -> (Vec<u8>, SocketAddr) {
            let (len, data_len) = self.unpack_udp_data_length(buf).unwrap();

            let mut data = vec![0; data_len];
            data.copy_from_slice(&buf[4..4 + data_len]);

            let addr = from_utf8(&buf[4 + data_len..4 + len])
                .unwrap()
                .parse()
                .unwrap();
            (data, addr)
        }
    }
}
