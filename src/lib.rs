#[macro_use]
extern crate log;
extern crate crc;
extern crate crypto;
extern crate time;
extern crate rand;
extern crate crossbeam_channel;
extern crate async_std;
extern crate futures_timer;

pub mod logger;
pub mod tcp;
// pub mod ucp;
pub mod timer;
pub mod client;
pub mod server;
pub mod socks5;
pub mod cryptor;

mod protocol {
    use std::vec::Vec;

    pub const VERIFY_DATA: [u8; 8] =
        [0xF0u8, 0xEF, 0xE, 0x2, 0xAE, 0xBC, 0x8C, 0x78];
    pub const HEARTBEAT_INTERVAL_MS: i64 = 5000;
    pub const ALIVE_TIMEOUT_TIME_MS: i64 = 60000;

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
        unsafe { *(buf.as_ptr().offset(1) as *mut u32) = id.to_be(); }
        buf
    }

    fn pack_cmd_id_data_msg(cmd: u8, id: u32, data: &[u8]) -> Vec<u8> {
        let mut buf = vec![0; 9 + data.len()];
        let len = data.len() as u32;

        write_cmd_id_len(&mut buf[..], cmd, id, len);
        buf[9..].copy_from_slice(data);

        buf
    }

    pub fn pack_cs_open_port_msg(id: u32) -> [u8; 5] {
        pack_cmd_id_msg(cs::OPEN_PORT, id)
    }

    pub fn pack_cs_connect_msg(id: u32, data: &[u8]) -> Vec<u8> {
        pack_cmd_id_data_msg(cs::CONNECT, id, data)
    }

    pub fn pack_cs_connect_domain_msg(
        id: u32, domain: &[u8], port: u16) -> Vec<u8> {
        let buf_len = 11 + domain.len();
        let mut buf = vec![0; buf_len];
        let len = domain.len() as u32 + 2;

        write_cmd_id_len(&mut buf[..], cs::CONNECT_DOMAIN_NAME, id, len);
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

    /*
    pub fn read_cmd(buf: &[u8]) -> u8 {
        buf[0]
    }

    pub fn read_id(buf: &[u8]) -> u32 {
        let id = unsafe { *(buf.as_ptr().offset(1) as *const u32) };
        u32::from_be(id)
    }

    pub fn read_id_len(buf: &[u8]) -> (u32, usize) {
        let id = unsafe { *(buf.as_ptr().offset(1) as *const u32) };
        let len = unsafe { *(buf.as_ptr().offset(5) as *const u32) };
        (u32::from_be(id), u32::from_be(len) as usize)
    }

    pub fn read_domain_port(buf: &[u8]) -> u16 {
        let total_len = get_total_packet_len(buf);
        let port = unsafe {
            let offset = (total_len - 2) as isize;
            *(buf.as_ptr().offset(offset) as *const u16)
        };
        u16::from_be(port)
    }

    pub fn get_total_packet_len(buf: &[u8]) -> usize {
        let (_, len) = read_id_len(buf);
        len + 9
    }
    */
}
