use std::net::TcpStream;
use std::net::Shutdown;
use std::io::Read;
use std::io::Write;
use std::io::Error;
use std::vec::Vec;

pub struct Tcp {
    stream: TcpStream
}

pub enum TcpError {
    Eof,
    ErrorData,
    IoError(Error),
}

impl Tcp {
    pub fn new(stream: TcpStream) -> Tcp {
        Tcp { stream: stream }
    }

    pub fn shutdown_read(&mut self) {
        let _ = self.stream.shutdown(Shutdown::Read);
    }

    pub fn shutdown_write(&mut self) {
        let _ = self.stream.shutdown(Shutdown::Write);
    }

    pub fn shutdown(&mut self) {
        let _ = self.stream.shutdown(Shutdown::Both);
    }

    pub fn read_u8(&mut self) -> Result<u8, TcpError> {
        let mut buf = [0u8];
        self.read_exact_buf(&mut buf)?;

        Ok(buf[0])
    }

    pub fn read_u16(&mut self) -> Result<u16, TcpError> {
        let mut buf = [0u8; 2];
        self.read_exact_buf(&mut buf)?;

        let result = unsafe { *(buf.as_ptr() as *const u16) };
        Ok(u16::from_be(result))
    }

    pub fn read_u32(&mut self) -> Result<u32, TcpError> {
        let mut buf = [0u8; 4];
        self.read_exact_buf(&mut buf)?;

        let result = unsafe { *(buf.as_ptr() as *const u32) };
        Ok(u32::from_be(result))
    }

    pub fn read_u64(&mut self) -> Result<u64, TcpError> {
        let mut buf = [0u8; 8];
        self.read_exact_buf(&mut buf)?;

        let result = unsafe { *(buf.as_ptr() as *const u64) };
        Ok(u64::from_be(result))
    }

    pub fn read_exact(&mut self, size: usize) -> Result<Vec<u8>, TcpError> {
        let mut buf = Vec::with_capacity(size);
        unsafe { buf.set_len(size); }

        self.read_exact_buf(&mut buf[..])?;
        Ok(buf)
    }

    pub fn read_exact_buf(&mut self, buf: &mut [u8]) -> Result<(), TcpError> {
        let size = buf.len();

        let mut length = 0;
        while length < size {
            match self.stream.read(&mut buf[length..]) {
                Ok(0) => return Err(TcpError::ErrorData),
                Ok(l) => length += l,
                Err(e) => return Err(TcpError::IoError(e))
            }
        }

        Ok(())
    }

    pub fn read_at_most(&mut self, size: usize) -> Result<Vec<u8>, TcpError> {
        let mut buf = Vec::with_capacity(size);
        unsafe { buf.set_len(size); }

        match self.stream.read(&mut buf[..]) {
            Ok(0) => return Err(TcpError::Eof),
            Ok(l) => unsafe { buf.set_len(l); },
            Err(e) => return Err(TcpError::IoError(e))
        }

        Ok(buf)
    }

    pub fn write_u8(&mut self, v: u8) -> Result<(), TcpError> {
        let buf = [v];
        self.write(&buf)
    }

    pub fn write_u16(&mut self, v: u16) -> Result<(), TcpError> {
        let buf = [0u8; 2];
        unsafe { *(buf.as_ptr() as *mut u16) = v.to_be(); }
        self.write(&buf)
    }

    pub fn write_u32(&mut self, v: u32) -> Result<(), TcpError> {
        let buf = [0u8; 4];
        unsafe { *(buf.as_ptr() as *mut u32) = v.to_be(); }
        self.write(&buf)
    }

    pub fn write_u64(&mut self, v: u64) -> Result<(), TcpError> {
        let buf = [0u8; 8];
        unsafe { *(buf.as_ptr() as *mut u64) = v.to_be(); }
        self.write(&buf)
    }

    pub fn write(&mut self, buf: &[u8]) -> Result<(), TcpError> {
        let size = buf.len();

        let mut length = 0;
        while length < size {
            match self.stream.write(&buf[length..]) {
                Ok(l) => length += l,
                Err(e) => return Err(TcpError::IoError(e))
            }
        }

        Ok(())
    }
}
