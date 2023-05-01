use std::vec::Vec;

use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand::{rngs::OsRng, RngCore};
use scrypt;

const SALT_SIZE: usize = 16;
const NONCE_SIZE: usize = 12;

pub struct Encryptor {
    cipher: ChaCha20Poly1305,
    salt: [u8; SALT_SIZE],
}

impl Encryptor {
    pub fn new(password: &[u8]) -> Self {
        let mut salt = [0u8; SALT_SIZE];
        OsRng.fill_bytes(&mut salt);

        let params = scrypt::Params::recommended();
        let mut secret_key = [0u8; scrypt::Params::RECOMMENDED_LEN];
        scrypt::scrypt(password, &salt, &params, &mut secret_key).unwrap();

        let cipher = ChaCha20Poly1305::new(&secret_key.into());
        Self { cipher, salt }
    }

    pub fn initialize_data(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.salt);
        data
    }

    pub fn encrypt(&mut self, data: &[u8]) -> Vec<u8> {
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let mut cipher_data = self.cipher.encrypt(&nonce, data).unwrap();
        cipher_data.extend_from_slice(nonce.as_slice());
        cipher_data
    }
}

pub struct Decryptor {
    cipher: ChaCha20Poly1305,
}

impl Decryptor {
    pub fn initialize_data() -> Vec<u8> {
        vec![0u8; SALT_SIZE]
    }

    pub fn new(password: &[u8], data: &[u8]) -> Option<Self> {
        if data.len() != SALT_SIZE {
            return None;
        }

        let params = scrypt::Params::recommended();
        let mut secret_key = [0u8; scrypt::Params::RECOMMENDED_LEN];
        scrypt::scrypt(password, data, &params, &mut secret_key).unwrap();

        let cipher = ChaCha20Poly1305::new(&secret_key.into());
        Some(Self { cipher })
    }

    pub fn decrypt(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        if data.len() <= NONCE_SIZE {
            return None;
        }

        let ciphertext_len = data.len() - NONCE_SIZE;
        let nonce = Nonce::from_slice(&data[ciphertext_len..]);
        self.cipher.decrypt(nonce, &data[0..ciphertext_len]).ok()
    }
}
