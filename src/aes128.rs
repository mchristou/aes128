use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    aes::cipher::typenum,
    Aes128Gcm, Key, KeySizeUser, Nonce,
};
use smallvec::SmallVec;

use crate::error::{Error, Result};

const BUFFER_SIZE: usize = 2048;
const TAG_SIZE: usize = 16;

pub struct Aes128 {
    cipher: Aes128Gcm,
    nonce: Nonce<typenum::U12>,
}

impl Aes128 {
    pub fn new(key: &[u8]) -> Result<Self> {
        if key.len() < Aes128Gcm::key_size() {
            return Err(Error::InvalidKeyLength(key.len()));
        }

        let key = Key::<Aes128Gcm>::from_slice(key);

        let cipher = Aes128Gcm::new(key);
        let nonce = Aes128Gcm::generate_nonce(&mut OsRng);

        Ok(Self { cipher, nonce })
    }

    pub fn encrypt(&self, input: &[u8], output: &mut SmallVec<[u8; BUFFER_SIZE]>) -> Result<()> {
        let size = self.calculate_encr_size(input.len());
        output.resize(size, 0);

        let enc_data = self
            .cipher
            .encrypt(&self.nonce, input)
            .map_err(|e| Error::EncryptionFailed(e.to_string()))?;

        output[..].copy_from_slice(&enc_data[..]);

        Ok(())
    }

    pub fn decrypt(&self, input: &[u8], output: &mut SmallVec<[u8; BUFFER_SIZE]>) -> Result<()> {
        let size = self.calculate_decr_size(input.len());
        output.resize(size, 0);

        let enc_data = self
            .cipher
            .decrypt(&self.nonce, input)
            .map_err(|e| Error::DecryptionFailed(e.to_string()))?;

        output[..].copy_from_slice(&enc_data[..]);

        Ok(())
    }

    fn calculate_encr_size(&self, input_encoded_len: usize) -> usize {
        input_encoded_len + TAG_SIZE
    }

    fn calculate_decr_size(&self, input_encoded_len: usize) -> usize {
        input_encoded_len - TAG_SIZE
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smallvec::smallvec;

    #[test]
    fn simple() {
        let key: &[u8; 16] = &[
            0x4d, 0x79, 0x53, 0x65, 0x63, 0x72, 0x65, 0x74, 0x4b, 0x65, 0x79, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];

        let aes = Aes128::new(key).unwrap();
        let plain_text = "simple test";

        let mut encrypted_data = smallvec![];
        aes.encrypt(plain_text.as_bytes(), &mut encrypted_data)
            .unwrap();

        let mut decrypted_data = smallvec![];
        aes.decrypt(encrypted_data.as_slice(), &mut decrypted_data)
            .unwrap();

        assert_eq!(plain_text.as_bytes(), decrypted_data.as_slice());
    }

    #[test]
    fn random_input() {
        let key: &[u8; 16] = &[
            0x4d, 0x79, 0x53, 0x65, 0x63, 0x72, 0x65, 0x74, 0x4b, 0x65, 0x79, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];

        let aes = Aes128::new(key).unwrap();
        let plain_text = "Ka1TT1xP4jCtr35m4yO5T4P14s03JVOQDC8BInDjKBFSM9wkiHDZGDl";

        let mut encrypted_data = smallvec![];
        aes.encrypt(plain_text.as_bytes(), &mut encrypted_data)
            .unwrap();

        let mut decrypted_data = smallvec![];
        aes.decrypt(encrypted_data.as_slice(), &mut decrypted_data)
            .unwrap();

        assert_eq!(plain_text.as_bytes(), decrypted_data.as_slice());
    }

    #[test]
    fn input_length_over_255() {
        let key: &[u8; 16] = &[
            0xC9, 0x10, 0xC4, 0x12, 0x11, 0xE5, 0x19, 0x80, 0xBA, 0x1E, 0xA8, 0x8B, 0x14, 0x76,
            0xEA, 0xEB,
        ];

        let aes = Aes128::new(key).unwrap();
        let plain_text = "Hg0L4uA24IgpY2XMhnu9FJ61wThB
                          cRKan04fF0XyxbJuuwlyTwbXNh4G
                          qQrXbvGvO70ePMBmovnVZnVULE5T
                          tHz16Jv7VSaM1gcKm50BOpDD4gXZ
                          OwWCU1boJHg8uRweqwoQc8RQg5F6
                          I4OjNF4sZYdXLTGjXj8oRD1daQye
                          HqCNbDty7DheySHMyD3XOhr8W7jp
                          786z92o9uvNLKSOh9nljcwYV9SHB
                          QzwqM2WkhPaBL9lAuBH3CL5NXK2";

        let mut encrypted_data = smallvec![];
        aes.encrypt(plain_text.as_bytes(), &mut encrypted_data)
            .unwrap();

        let mut decrypted_data = smallvec![];
        aes.decrypt(encrypted_data.as_slice(), &mut decrypted_data)
            .unwrap();

        assert_eq!(plain_text.as_bytes(), decrypted_data.as_slice());
    }
}
