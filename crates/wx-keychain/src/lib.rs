pub mod account_id;
pub mod error;
#[path = "mach_vm/mod.rs"]
pub mod memory_scan;
pub mod nickname;
pub mod process;
pub mod store;
#[cfg(windows)]
pub mod windows;
#[cfg(windows)]
mod windows_debug;

pub use account_id::AccountId;
pub use error::KeychainError;
pub use nickname::resolve_nickname;
pub use process::config_dir;
pub use process::detect_active_account;
pub use process::{
    ensure_supported_wechat_version, extract_base_wxid, find_account_dirs, find_account_dirs_under,
    find_wechat_pid, is_extraction_compatible, is_xwechat_files_root, AccountDirInfo,
    ActiveAccount, DetectionSource, SUPPORTED_VERSION,
};
pub use store::{AccountKey, EncKeyEntry, KeyStore};
#[cfg(windows)]
pub use windows::{
    capture_key_windows, capture_keys_windows, find_weixin_pids, installed_weixin_version,
    WindowsMemoryReader,
};
#[cfg(windows)]
pub use windows_debug::{capture_keys_windows_debug, launch_and_capture_keys_windows_debug};
pub use wx_decrypt::read_db_salt;

/// 单项前置条件检查的结果。
pub struct PreflightCheck {
    pub name: &'static str,
    pub passed: bool,
    pub detail: String,
    pub fix_cmd: Option<String>,
}

/// 运行所有前置条件检查，返回结果列表。
pub fn all_preflight_checks() -> Vec<PreflightCheck> {
    crate::windows::preflight_checks()
}

/// Pre-flight checks before key extraction.
///
/// Verifies the Windows prerequisites required for process-memory key extraction.
pub fn preflight_checks() -> Result<(), KeychainError> {
    for check in all_preflight_checks() {
        if !check.passed {
            return Err(KeychainError::Other(check.detail));
        }
    }
    Ok(())
}
