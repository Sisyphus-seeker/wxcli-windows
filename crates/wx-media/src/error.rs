use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum MediaError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("invalid dat format: {reason}")]
    InvalidFormat { reason: String },

    #[error("V2 AES key required but not provided")]
    MissingV2Key,

    #[error("AES decryption failed: {reason}")]
    AesDecryptFailed { reason: String },

    #[error("XOR key detection failed: no known image magic matched")]
    XorKeyDetectionFailed,

    #[error("resource not found: {0}")]
    NotFound(String),

    #[error("media lookup miss: {0}")]
    LookupMiss(String),

    #[error("media schema missing: {0}")]
    SchemaMissing(String),

    #[error("packed_info parse failed for local_id {local_id}: {reason}")]
    PackedInfoParseFailed { local_id: i64, reason: String },

    #[error("no dat files found for md5 {md5} under {path}")]
    NoDatFiles { md5: String, path: PathBuf },

    #[error("no media databases found in {0}")]
    NoMediaDbs(PathBuf),

    #[error("invalid or unsupported WXGF container")]
    InvalidWxgf,

    #[error("ffmpeg not found")]
    FfmpegNotFound,

    #[error("ffmpeg failed (exit {status}): {stderr}")]
    FfmpegFailed { status: i32, stderr: String },

    #[error("SILK decode failed: {reason}")]
    SilkDecodeFailed { reason: String },

    #[error("audio feature not enabled (build with --features audio)")]
    AudioFeatureDisabled,
}

impl MediaError {
    pub fn ffmpeg_install_hint() -> &'static str {
        "install ffmpeg and ensure it is on PATH, or set FFMPEG_PATH to the ffmpeg binary"
    }
}
