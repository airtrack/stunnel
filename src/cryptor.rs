use std::vec::Vec;
use rand;
use crypto::blowfish::Blowfish;
use crypto::blockmodes::CtrMode;
use crypto::symmetriccipher::{Encryptor, Decryptor};
use crypto::buffer::{
    RefReadBuffer, RefWriteBuffer, ReadBuffer, WriteBuffer, BufferResult
};

pub struct Cryptor {
    cryptor: CtrMode<Blowfish>,
    ctr: Vec<u8>,
}

impl Cryptor {
    pub fn new(key: &[u8]) -> Cryptor {
        let mut ctr = vec![0u8, 0, 0, 0, 0, 0, 0, 0];
        for x in ctr.iter_mut() {
            *x = rand::random::<u8>()
        }

        Cryptor::with_ctr(key, ctr)
    }

    pub fn with_ctr(key: &[u8], ctr: Vec<u8>) -> Cryptor {
        let algo = Blowfish::new(key);
        let cryptor = CtrMode::new(algo, ctr.clone());
        Cryptor { cryptor: cryptor, ctr: ctr }
    }

    pub fn key_size_range() -> (usize, usize) {
        (4, 56)
    }

    pub fn ctr_size() -> usize {
        8
    }

    pub fn ctr_as_slice(&self) -> &[u8] {
        &self.ctr[..]
    }

    pub fn encrypt(&mut self, data: &[u8]) -> Vec<u8> {
        let mut result = Vec::<u8>::new();
        let mut read_buffer = RefReadBuffer::new(data);
        let mut buffer = [0; 2048];
        let mut write_buffer = RefWriteBuffer::new(&mut buffer);

        loop {
            let res = self.cryptor.encrypt(
                &mut read_buffer, &mut write_buffer, false).unwrap();
            result.extend(write_buffer.take_read_buffer().
                          take_remaining().iter().map(|&i| i));

            match res {
                BufferResult::BufferUnderflow => break,
                BufferResult::BufferOverflow => {}
            }
        }

        result
    }

    pub fn decrypt(&mut self, data: &[u8]) -> Vec<u8> {
        let mut result = Vec::<u8>::new();
        let mut read_buffer = RefReadBuffer::new(data);
        let mut buffer = [0; 2048];
        let mut write_buffer = RefWriteBuffer::new(&mut buffer);

        loop {
            let res = self.cryptor.decrypt(
                &mut read_buffer, &mut write_buffer, false).unwrap();
            result.extend(write_buffer.take_read_buffer().
                          take_remaining().iter().map(|&i| i));

            match res {
                BufferResult::BufferUnderflow => break,
                BufferResult::BufferOverflow => {}
            }
        }

        result
    }
}
