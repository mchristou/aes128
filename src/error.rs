use thiserror::Error;

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Invalid length: {0}")]
    InvalidLength(usize),

    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
}
