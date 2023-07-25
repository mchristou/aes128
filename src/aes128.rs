use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    aes::cipher::typenum,
    Aes128Gcm, Key, Nonce,
};

use crate::error::{Error, Result};

pub struct Aes128 {
    cipher: Aes128Gcm,
    nonce: Nonce<typenum::U12>,
}

impl Aes128 {
    const KEY_LENGTH: usize = 16;

    pub fn new(key: &[u8]) -> Result<Self> {
        let key = Self::validate_key(key)?;
        let key = Key::<Aes128Gcm>::from_slice(key.as_slice());

        let cipher = Aes128Gcm::new(&key);
        let nonce = Aes128Gcm::generate_nonce(&mut OsRng);

        Ok(Self { cipher, nonce })
    }

    pub fn encrypt(&self, plain_text: &[u8]) -> Result<Vec<u8>> {
        let encrypted_data = self
            .cipher
            .encrypt(&self.nonce, plain_text)
            .map_err(|e| Error::EncryptionFailed(e.to_string()))?;

        Ok(encrypted_data)
    }

    pub fn decrypt(&self, encrypted_data: &[u8]) -> Result<Vec<u8>> {
        let decrypted_data = self
            .cipher
            .decrypt(&self.nonce, encrypted_data)
            .map_err(|e| Error::EncryptionFailed(e.to_string()))?;

        Ok(decrypted_data)
    }

    fn validate_key(key: &[u8]) -> Result<Vec<u8>> {
        if key.len() == Self::KEY_LENGTH {
            return Ok(key.to_owned());
        }

        if key.len() < Self::KEY_LENGTH {
            let mut key = key.to_owned();
            for _ in 0..(Self::KEY_LENGTH - key.len()) {
                key.push(0x00);
            }

            return Ok(key);
        }

        return Err(Error::InvalidLength(key.len()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smaller_key() {
        let key: &[u8] = &[
            0x4d, 0x79, 0x53, 0x65, 0x63, 0x72, 0x65, 0x74, 0x4b, 0x65, 0x79, 0x00, 0x00,
        ];

        let aes = Aes128::new(key).unwrap();
        let plain_text = "key is smaller than 16 bytes";

        let encrypted_data = aes.encrypt(plain_text.as_bytes()).unwrap();
        let decrypted_data = aes.decrypt(encrypted_data.as_slice()).unwrap();

        assert_eq!(plain_text.as_bytes(), decrypted_data);
    }

    #[test]
    fn encrypt_decrypt() {
        let key: &[u8; 16] = &[
            0x4d, 0x79, 0x53, 0x65, 0x63, 0x72, 0x65, 0x74, 0x4b, 0x65, 0x79, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];

        let aes = Aes128::new(key).unwrap();
        let plain_text = "My Simple test";

        let encrypted_data = aes.encrypt(plain_text.as_bytes()).unwrap();
        let decrypted_data = aes.decrypt(encrypted_data.as_slice()).unwrap();

        assert_eq!(plain_text.as_bytes(), decrypted_data);
    }
}
