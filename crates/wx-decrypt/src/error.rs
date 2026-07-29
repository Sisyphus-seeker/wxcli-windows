use thiserror::Error;

#[derive(Debug, Error)]
pub enum DecryptError {
    #[error("file too small: expected at least {expected} bytes, got {actual}")]
    FileTooSmall { expected: usize, actual: usize },

    #[error("database is already decrypted (SQLite header detected)")]
    AlreadyDecrypted,

    #[error("incorrect key: HMAC verification failed on first page")]
    IncorrectKey,

    #[error("salt mismatch: DB salt does not match provided salt")]
    SaltMismatch,

    #[error("no matching enc_key found for this DB's salt")]
    NoMatchingEncKey,

    #[error("HMAC verification failed on page {page_num}")]
    HmacVerificationFailed { page_num: u32 },

    #[error("AES decryption failed on page {page_num}: {reason}")]
    AesDecryptFailed { page_num: u32, reason: String },

    #[error("invalid WAL header: {reason}")]
    InvalidWalHeader { reason: String },

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
