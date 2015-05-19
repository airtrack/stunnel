use std::net::TcpStream;
use std::net::Shutdown;
use std::io::Read;
use std::io::Write;
use std::io::Error;
use std::io::ErrorKind;
use std::vec::Vec;

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

    pub fn read_u8(&mut self) -> Result<u8, Error> {
        let mut buf = [0u8];
        try!(self.read_exact_buf(&mut buf));

        Ok(buf[0])
    }

    pub fn read_u16(&mut self) -> Result<u16, Error> {
        let mut buf = [0u8; 2];
        try!(self.read_exact_buf(&mut buf));

        let result = unsafe { *(buf.as_ptr() as *const u16) };
        Ok(u16::from_be(result))
    }

    pub fn read_u32(&mut self) -> Result<u32, Error> {
        let mut buf = [0u8; 4];
        try!(self.read_exact_buf(&mut buf));

        let result = unsafe { *(buf.as_ptr() as *const u32) };
        Ok(u32::from_be(result))
    }

    pub fn read_u64(&mut self) -> Result<u64, Error> {
        let mut buf = [0u8; 8];
        try!(self.read_exact_buf(&mut buf));

        let result = unsafe { *(buf.as_ptr() as *const u64) };
        Ok(u64::from_be(result))
    }

    pub fn read_exact(&mut self, size: usize) -> Result<Vec<u8>, Error> {
        let mut buf = Vec::with_capacity(size);
        unsafe { buf.set_len(size); }

        try!(self.read_exact_buf(&mut buf[..]));
        Ok(buf)
    }

    pub fn read_exact_buf(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        let size = buf.len();

        let mut length = 0;
        while length < size {
            let len = try!(self.stream.read(&mut buf[length..]));
            if len == 0 {
                return Err(Error::new(ErrorKind::Other, "eof"));
            } else {
                length += len;
            }
        }

        Ok(())
    }

    pub fn read_at_most(&mut self, size: usize) -> Result<Vec<u8>, Error> {
        let mut buf = Vec::with_capacity(size);
        unsafe { buf.set_len(size); }

        let len = try!(self.stream.read(&mut buf[..]));
        if len == 0 {
            return Err(Error::new(ErrorKind::Other, "eof"));
        } else {
            unsafe { buf.set_len(len); }
        }

        Ok(buf)
    }

    pub fn write_u8(&mut self, v: u8) -> Result<(), Error> {
        let buf = [v];
        self.write(&buf)
    }

    pub fn write_u16(&mut self, v: u16) -> Result<(), Error> {
        let buf = [0u8; 2];
        unsafe { *(buf.as_ptr() as *mut u16) = v.to_be(); }
        self.write(&buf)
    }

    pub fn write_u32(&mut self, v: u32) -> Result<(), Error> {
        let buf = [0u8; 4];
        unsafe { *(buf.as_ptr() as *mut u32) = v.to_be(); }
        self.write(&buf)
    }

    pub fn write_u64(&mut self, v: u64) -> Result<(), Error> {
        let buf = [0u8; 8];
        unsafe { *(buf.as_ptr() as *mut u64) = v.to_be(); }
        self.write(&buf)
    }

    pub fn write(&mut self, buf: &[u8]) -> Result<(), Error> {
        let size = buf.len();

        let mut length = 0;
        while length < size {
            length += try!(self.stream.write(&buf[length..]));
        }

        Ok(())
    }
}
