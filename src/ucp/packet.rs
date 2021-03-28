use crate::ucp::*;
use crc::crc32;
use std::cmp::min;
use std::collections::VecDeque;

#[derive(Clone)]
pub(super) struct UcpPacket {
    read_pos: usize,
    pub(super) buf: [u8; 1400],
    pub(super) size: usize,
    pub(super) payload: u16,
    pub(super) skip_times: u32,

    pub(super) session_id: u32,
    pub(super) timestamp: u32,
    pub(super) window: u32,
    pub(super) xmit: u32,
    pub(super) una: u32,
    pub(super) seq: u32,
    pub(super) cmd: u8,
}

impl UcpPacket {
    pub(super) fn new() -> UcpPacket {
        UcpPacket {
            buf: [0; 1400],
            read_pos: 0,
            size: 0,
            payload: 0,
            skip_times: 0,
            session_id: 0,
            timestamp: 0,
            window: 0,
            xmit: 0,
            una: 0,
            seq: 0,
            cmd: 0,
        }
    }

    pub(super) fn size(&self) -> usize {
        self.payload as usize + UCP_PACKET_META_SIZE
    }

    pub(super) fn parse(&mut self) -> bool {
        if !self.is_legal() {
            return false;
        }

        self.payload = (self.size - UCP_PACKET_META_SIZE) as u16;
        self.read_pos = UCP_PACKET_META_SIZE;

        let mut offset = 4;
        self.session_id = self.parse_u32(&mut offset);
        self.timestamp = self.parse_u32(&mut offset);
        self.window = self.parse_u32(&mut offset);
        self.xmit = self.parse_u32(&mut offset);
        self.una = self.parse_u32(&mut offset);
        self.seq = self.parse_u32(&mut offset);
        self.cmd = self.parse_u8(&mut offset);

        self.cmd >= CMD_SYN && self.cmd <= CMD_HEARTBEAT_ACK
    }

    pub(super) fn pack(&mut self) {
        let mut offset = 4;
        let session_id = self.session_id;
        let timestamp = self.timestamp;
        let window = self.window;
        let xmit = self.xmit;
        let una = self.una;
        let seq = self.seq;
        let cmd = self.cmd;

        self.write_u32(&mut offset, session_id);
        self.write_u32(&mut offset, timestamp);
        self.write_u32(&mut offset, window);
        self.write_u32(&mut offset, xmit);
        self.write_u32(&mut offset, una);
        self.write_u32(&mut offset, seq);
        self.write_u8(&mut offset, cmd);

        offset = 0;
        self.size = self.payload as usize + UCP_PACKET_META_SIZE;

        let digest = crc32::checksum_ieee(&self.buf[4..self.size]);
        self.write_u32(&mut offset, digest);
    }

    pub(super) fn packed_buffer(&self) -> &[u8] {
        &self.buf[..self.size]
    }

    pub(super) fn parse_u32(&self, offset: &mut isize) -> u32 {
        let u = unsafe { *(self.buf.as_ptr().offset(*offset) as *const u32) };

        *offset += 4;
        u32::from_be(u)
    }

    pub(super) fn parse_u8(&self, offset: &mut isize) -> u8 {
        let u = self.buf[*offset as usize];
        *offset += 1;
        u
    }

    pub(super) fn write_u32(&mut self, offset: &mut isize, u: u32) {
        unsafe {
            *(self.buf.as_ptr().offset(*offset) as *mut u32) = u.to_be();
        }

        *offset += 4;
    }

    pub(super) fn write_u8(&mut self, offset: &mut isize, u: u8) {
        self.buf[*offset as usize] = u;
        *offset += 1;
    }

    pub(super) fn is_legal(&self) -> bool {
        self.size >= UCP_PACKET_META_SIZE && self.is_crc32_correct()
    }

    pub(super) fn is_crc32_correct(&self) -> bool {
        let mut offset = 0;
        let digest = self.parse_u32(&mut offset);
        crc32::checksum_ieee(&self.buf[4..self.size]) == digest
    }

    pub(super) fn is_syn(&self) -> bool {
        self.cmd == CMD_SYN
    }

    pub(super) fn remaining_load(&self) -> usize {
        self.buf.len() - self.payload as usize - UCP_PACKET_META_SIZE
    }

    pub(super) fn payload_offset(&self) -> isize {
        (self.payload as usize + UCP_PACKET_META_SIZE) as isize
    }

    pub(super) fn payload_write_u32(&mut self, u: u32) -> bool {
        if self.remaining_load() >= 4 {
            let mut offset = self.payload_offset();
            self.write_u32(&mut offset, u);
            self.payload += 4;
            true
        } else {
            false
        }
    }

    pub(super) fn payload_write_slice(&mut self, buf: &[u8]) -> bool {
        if self.remaining_load() >= buf.len() {
            let offset = self.payload_offset() as usize;
            let end = offset + buf.len();
            self.buf[offset..end].copy_from_slice(buf);
            self.payload += buf.len() as u16;
            true
        } else {
            false
        }
    }

    pub(super) fn payload_remaining(&self) -> usize {
        self.size - self.read_pos
    }

    pub(super) fn payload_read_u32(&mut self) -> u32 {
        if self.read_pos + 4 > self.size {
            panic!("Out of range when read u32 from {}", self.read_pos);
        }

        let mut offset = self.read_pos as isize;
        let u = self.parse_u32(&mut offset);
        self.read_pos = offset as usize;
        u
    }

    pub(super) fn payload_read_slice(&mut self, buf: &mut [u8]) -> usize {
        let size = min(self.payload_remaining(), buf.len());
        let end_pos = self.read_pos + size;

        if size > 0 {
            buf[0..size].copy_from_slice(&self.buf[self.read_pos..end_pos]);
            self.read_pos = end_pos;
        }

        size
    }
}

pub(super) type UcpPacketQueue = VecDeque<Box<UcpPacket>>;
