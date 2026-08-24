use thiserror::Error;

#[derive(Debug, Error)]
pub enum KeychainError {
    #[error("WeChat is not running")]
    WeChatNotRunning,

    #[error("WeChat version {version} is not supported for key extraction on this platform")]
    UnsupportedVersion { version: String },

    #[error("could not detect WeChat account directory")]
    AccountNotDetected,

    #[error("cannot detect active account: {reason}\nCandidates:\n{candidates}")]
    AccountDetectionFailed { reason: String, candidates: String },

    #[error("no valid enc_key found in WeChat process memory")]
    NoKeysFound,

    #[error("key store error: {0}")]
    Store(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Other(String),
}
