use std::net::TcpStream;
use std::net::Shutdown;
use std::io::Read;
use std::io::Write;
use std::vec::Vec;
use std::option::Option;

pub struct Tcp {
    stream: TcpStream
}

impl Tcp {
    pub fn new(stream: TcpStream) -> Tcp {
        Tcp { stream: stream }
    }

    pub fn shutdown(&self) {
        let _ = self.stream.shutdown(Shutdown::Both);
    }

    pub fn read_u8(&mut self) -> Option<u8> {
        let mut buf = [0u8];

        if self.read_exact_buf(&mut buf) {
            Some(buf[0])
        } else {
            None
        }
    }

    pub fn read_u16(&mut self) -> Option<u16> {
        let mut buf = [0u8; 2];

        if self.read_exact_buf(&mut buf) {
            let result = unsafe { *(buf.as_ptr() as *const u16) };
            Some(u16::from_be(result))
        } else {
            None
        }
    }

    pub fn read_u32(&mut self) -> Option<u32> {
        let mut buf = [0u8; 4];

        if self.read_exact_buf(&mut buf) {
            let result = unsafe { *(buf.as_ptr() as *const u32) };
            Some(u32::from_be(result))
        } else {
            None
        }
    }

    pub fn read_u64(&mut self) -> Option<u64> {
        let mut buf = [0u8; 8];
        if self.read_exact_buf(&mut buf) {
            let result = unsafe { *(buf.as_ptr() as *const u64) };
            Some(u64::from_be(result))
        } else {
            None
        }
    }

    pub fn read_exact(&mut self, size: usize) -> Vec<u8> {
        let mut buf = Vec::with_capacity(size);
        unsafe { buf.set_len(size); }

        if !self.read_exact_buf(&mut buf[..]) {
            unsafe { buf.set_len(0); }
        }

        buf
    }

    pub fn read_exact_buf(&mut self, buf: &mut [u8]) -> bool {
        let size = buf.len();

        let mut length = 0;
        while length < size {
            match self.stream.read(&mut buf[length..]) {
                Ok(len) => {
                    if len == 0 {
                        return false
                    } else {
                        length += len;
                    }
                },
                Err(_) => {
                    return false
                }
            }
        }

        return true
    }

    pub fn read_at_most(&mut self, size: usize) -> Vec<u8> {
        let mut buf = Vec::with_capacity(size);
        unsafe { buf.set_len(size); }

        match self.stream.read(&mut buf[..]) {
            Ok(len) => {
                unsafe { buf.set_len(len); }
            },
            Err(_) => {
                unsafe { buf.set_len(0); }
            }
        }

        buf
    }

    pub fn write_u8(&mut self, v: u8) -> bool {
        let buf = [v];
        self.write(&buf)
    }

    pub fn write_u16(&mut self, v: u16) -> bool {
        let buf = [0u8; 2];
        unsafe { *(buf.as_ptr() as *mut u16) = v.to_be(); }
        self.write(&buf)
    }

    pub fn write_u32(&mut self, v: u32) -> bool {
        let buf = [0u8; 4];
        unsafe { *(buf.as_ptr() as *mut u32) = v.to_be(); }
        self.write(&buf)
    }

    pub fn write_u64(&mut self, v: u64) -> bool {
        let buf = [0u8; 8];
        unsafe { *(buf.as_ptr() as *mut u64) = v.to_be(); }
        self.write(&buf)
    }

    pub fn write(&mut self, buf: &[u8]) -> bool {
        let size = buf.len();

        let mut length = 0;
        while length < size {
            match self.stream.write(&buf[length..]) {
                Ok(len) => { length += len; },
                Err(_) => return false
            }
        }

        return true
    }
}
