use thiserror::Error;

#[derive(Debug, Error)]
pub enum ContextError {
    #[error("keychain: {0}")]
    Keychain(#[from] wx_keychain::KeychainError),

    #[error("database: {0}")]
    Db(#[from] wx_db::DbError),

    #[error("decrypt: {0}")]
    Decrypt(#[from] wx_decrypt::DecryptError),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("no account found: {0}")]
    NoAccount(String),

    #[error("no key for account {0}: use `key extract` or `-k`")]
    NoKey(String),

    #[error("cache: {0}")]
    Cache(String),

    #[error("sqlite: {0}")]
    Sqlite(String),
}
