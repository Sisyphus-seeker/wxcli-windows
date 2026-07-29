use thiserror::Error;

#[derive(Debug, Error)]
pub enum KeychainError {
    #[error("SIP (System Integrity Protection) is not disabled — run `csrutil disable` in Recovery Mode")]
    SipEnabled,

    #[error("DevToolsSecurity is not enabled — run `sudo DevToolsSecurity -enable`")]
    DevToolsSecurityDisabled,

    #[error("{0} is not in _developer group — run `sudo dscl . -append /Groups/_developer GroupMembership {0}`")]
    NotInDeveloperGroup(String),

    #[error("LLDB not found — install Xcode Command Line Tools: `xcode-select --install`")]
    LldbNotFound,

    #[error("python3 not found — install Xcode Command Line Tools: `xcode-select --install`")]
    Python3NotFound,

    #[error("WeChat is not running")]
    WeChatNotRunning,

    #[error("WeChat version {version} is not supported for key extraction on this platform")]
    UnsupportedVersion { version: String },

    #[error("could not detect WeChat account directory")]
    AccountNotDetected,

    #[error("cannot detect active account: {reason}\nCandidates:\n{candidates}")]
    AccountDetectionFailed { reason: String, candidates: String },

    #[error("LLDB capture timed out after {seconds}s — did you log in to WeChat?")]
    CaptureTimeout { seconds: u64 },

    #[error("no PBKDF2 calls with rounds=256000 found in LLDB output")]
    NoPbkdfCalls,

    #[error("captured key does not match target account salt")]
    KeySaltMismatch,

    #[error("task_for_pid failed for PID {pid} (kern_return={kr}) — ensure SIP is disabled (csrutil disable in Recovery Mode) and run with sudo")]
    TaskForPidFailed { pid: u32, kr: i32 },

    #[error("no valid enc_key found in WeChat process memory")]
    NoKeysFound,

    #[error("key store error: {0}")]
    Store(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Other(String),
}
