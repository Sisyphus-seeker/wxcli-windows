use thiserror::Error;

/// Errors that can occur during monitoring.
#[derive(Debug, Error)]
pub enum MonitorError {
    #[error("watcher error: {0}")]
    Watcher(#[from] notify::Error),
    #[error("decrypt error: {0}")]
    Decrypt(#[from] wx_decrypt::DecryptError),
    #[error("database error: {0}")]
    Db(#[from] wx_db::DbError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("data directory not found: {0}")]
    DataDirNotFound(String),
}
