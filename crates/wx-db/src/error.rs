use serde::{Deserialize, Serialize};
use thiserror::Error;

/// A non-fatal warning about a shard that was skipped during query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardWarning {
    pub path: String,
    pub reason: String,
}

/// Errors that can occur when opening or querying a WeChat database.
#[derive(Debug, Error)]
pub enum DbError {
    /// A required file or directory was not found at the given path.
    #[error("path not found: {0}")]
    NotFound(String),
    /// No message shard database files (`message_N.db`) were found.
    #[error("no message shards found")]
    NoShards,
    /// An error from the underlying SQLite layer.
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// An error during zstd decompression of message content.
    #[error("zstd error: {0}")]
    Zstd(String),
    /// An error applying the encryption key (sqlite3_key failed or wrong key).
    #[error("encryption key error: {0}")]
    EncryptionKey(String),
    /// An error during FTS tokenizer initialization.
    #[error("fts init error: {0}")]
    FtsInit(String),
    /// An I/O error (e.g. reading the message shard directory).
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
