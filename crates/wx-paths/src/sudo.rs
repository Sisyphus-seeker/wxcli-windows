use std::path::{Path, PathBuf};

use crate::PathsError;

/// Resolve the real user's home directory, even under `sudo -H`.
///
/// When `SUDO_USER` is set, uses `libc::getpwnam()` to look up the original
/// user's home directory. Otherwise falls back to `dirs::home_dir()`.
pub(crate) fn resolve_real_home() -> Result<PathBuf, PathsError> {
    #[cfg(unix)]
    {
        if let Ok(sudo_user) = std::env::var("SUDO_USER") {
            if !sudo_user.is_empty() {
                if let Some(home) = home_from_getpwnam(&sudo_user) {
                    return Ok(home);
                }
            }
        }
    }
    dirs::home_dir().ok_or(PathsError::NoHome)
}

#[cfg(unix)]
fn home_from_getpwnam(username: &str) -> Option<PathBuf> {
    use std::ffi::{CStr, CString};
    let c_user = CString::new(username).ok()?;
    // Safety: getpwnam returns a pointer to a static struct or null.
    let pw = unsafe { libc::getpwnam(c_user.as_ptr()) };
    if pw.is_null() {
        return None;
    }
    // Safety: pw_dir is a valid C string if pw is non-null.
    let home_cstr = unsafe { CStr::from_ptr((*pw).pw_dir) };
    let home_str = home_cstr.to_str().ok()?;
    Some(PathBuf::from(home_str))
}

/// Best-effort chown to the real user when running under sudo.
///
/// Reads `SUDO_UID` and `SUDO_GID` environment variables and uses `libc::chown()`
/// to restore ownership. Silently does nothing if not running under sudo or if
/// the chown fails (e.g. on non-Unix platforms).
pub fn chown_to_sudo_user(path: &Path) {
    #[cfg(unix)]
    {
        use std::ffi::CString;
        let uid: u32 = match std::env::var("SUDO_UID").ok().and_then(|v| v.parse().ok()) {
            Some(uid) => uid,
            None => return,
        };
        let gid: u32 = std::env::var("SUDO_GID")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(uid);
        if let Some(c_path) = path.to_str().and_then(|s| CString::new(s).ok()) {
            unsafe {
                libc::chown(c_path.as_ptr(), uid, gid);
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}
