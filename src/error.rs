use thiserror::Error;

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Invalid key length: {0}")]
    InvalidKeyLength(usize),

    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Encryption failed: {0}")]
    DecryptionFailed(String),
}
