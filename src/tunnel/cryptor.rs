use std::vec::Vec;

use chacha20poly1305::{
    aead::generic_array::typenum::Unsigned,
    aead::{Aead, AeadCore, KeyInit},
    ChaCha20Poly1305, Key, KeySizeUser, Nonce,
};
use rand::{rngs::OsRng, RngCore};
use scrypt;

const SALT_SIZE: usize = 16;
const HANDSHAKE_MESSAGE: [u8; 8] = [0xba, 0xd0, 0xba, 0xd1, 0xba, 0xd2, 0xba, 0xd3];

type Cipher = ChaCha20Poly1305;
struct CipherMeta;

impl CipherMeta {
    const fn salt_size() -> usize {
        SALT_SIZE
    }

    fn nonce_size() -> usize {
        <Cipher as AeadCore>::NonceSize::to_usize()
    }

    fn tag_size() -> usize {
        <Cipher as AeadCore>::TagSize::to_usize()
    }

    fn key_size() -> usize {
        <Cipher as KeySizeUser>::key_size()
    }

    fn handshake_message() -> &'static [u8] {
        &HANDSHAKE_MESSAGE
    }

    fn handshake_cipher_size() -> usize {
        Self::salt_size() + Self::handshake_message().len() + Self::tag_size() + Self::nonce_size()
    }

    fn new_cipher(password: &[u8], salt: &[u8]) -> Cipher {
        let params = scrypt::Params::new(10, 8, 1, Self::key_size()).unwrap();
        let mut secret_key = Key::default();
        scrypt::scrypt(password, &salt, &params, &mut secret_key).unwrap();
        Cipher::new(&secret_key)
    }
}

pub struct Encryptor {
    cipher: Cipher,
    salt: [u8; CipherMeta::salt_size()],
}

impl Encryptor {
    pub fn new(password: &[u8]) -> Self {
        let mut salt = [0u8; CipherMeta::salt_size()];
        OsRng.fill_bytes(&mut salt);

        let cipher = CipherMeta::new_cipher(password, &salt);
        Self { cipher, salt }
    }

    pub fn handshake(&mut self) -> Vec<u8> {
        let mut handshake = Vec::new();
        handshake.extend_from_slice(&self.salt);

        let message_cipher = self.encrypt(CipherMeta::handshake_message());
        handshake.extend_from_slice(&message_cipher);
        handshake
    }

    pub fn encrypt(&mut self, data: &[u8]) -> Vec<u8> {
        let nonce = Cipher::generate_nonce(&mut OsRng);
        let mut cipher_data = self.cipher.encrypt(&nonce, data).unwrap();
        cipher_data.extend_from_slice(nonce.as_slice());
        cipher_data
    }
}

pub struct Decryptor {
    cipher: Cipher,
}

impl Decryptor {
    pub fn handshake() -> Vec<u8> {
        vec![0u8; CipherMeta::handshake_cipher_size()]
    }

    pub fn new(password: &[u8], handshake: &[u8]) -> Option<Self> {
        if handshake.len() != CipherMeta::handshake_cipher_size() {
            return None;
        }

        let salt = &handshake[0..CipherMeta::salt_size()];
        let cipher = CipherMeta::new_cipher(password, salt);
        let mut decryptor = Self { cipher };

        match decryptor
            .decrypt(&handshake[CipherMeta::salt_size()..])
            .map(|handshake| &handshake == CipherMeta::handshake_message())
        {
            Some(true) => Some(decryptor),
            _ => None,
        }
    }

    pub fn decrypt(&mut self, data: &[u8]) -> Option<Vec<u8>> {
        if data.len() <= CipherMeta::nonce_size() {
            return None;
        }

        let ciphertext_len = data.len() - CipherMeta::nonce_size();
        let nonce = Nonce::from_slice(&data[ciphertext_len..]);
        self.cipher.decrypt(nonce, &data[0..ciphertext_len]).ok()
    }
}
