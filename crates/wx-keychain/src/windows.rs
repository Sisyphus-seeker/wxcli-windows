use std::collections::HashMap;
use std::mem::{size_of, zeroed};
use std::path::{Path, PathBuf};

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Memory::{
    VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_COMMIT, PAGE_EXECUTE_READ,
    PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY, PAGE_GUARD, PAGE_NOACCESS, PAGE_READONLY,
    PAGE_READWRITE, PAGE_WRITECOPY,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
};

use crate::error::KeychainError;
use crate::mach_vm::{self, MemRegion, MemoryCaptureResult, MemoryReader};
use crate::process::AccountDirInfo;
use crate::PreflightCheck;
use wx_decrypt::{EncKeyPair, KeyMaterial};

const PROCESS_NAMES: &[&str] = &["Weixin.exe", "WeChat.exe"];

pub fn find_weixin_pid() -> Result<u32, KeychainError> {
    find_weixin_pids()?
        .into_iter()
        .next()
        .ok_or(KeychainError::WeChatNotRunning)
}

pub fn find_weixin_pids() -> Result<Vec<u32>, KeychainError> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(std::io::Error::last_os_error().into());
        }

        let mut entry: PROCESSENTRY32W = zeroed();
        entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;
        let mut found = Vec::new();
        if Process32FirstW(snapshot, &mut entry) != 0 {
            loop {
                let end = entry
                    .szExeFile
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(entry.szExeFile.len());
                let name = String::from_utf16_lossy(&entry.szExeFile[..end]);
                if PROCESS_NAMES
                    .iter()
                    .any(|candidate| name.eq_ignore_ascii_case(candidate))
                {
                    found.push(entry.th32ProcessID);
                }
                if Process32NextW(snapshot, &mut entry) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snapshot);
        found.sort_unstable();
        found.dedup();
        if found.is_empty() {
            Err(KeychainError::WeChatNotRunning)
        } else {
            Ok(found)
        }
    }
}

pub fn installed_weixin_version() -> Result<String, KeychainError> {
    let mut roots = Vec::new();
    for variable in ["ProgramFiles", "ProgramFiles(x86)"] {
        if let Some(value) = std::env::var_os(variable) {
            roots.push(PathBuf::from(value).join("Tencent").join("Weixin"));
        }
    }
    roots.push(PathBuf::from(r"C:\Program Files\Tencent\Weixin"));

    roots
        .iter()
        .filter_map(|root| newest_version_dir(root))
        .max_by(|a, b| version_parts(a).cmp(&version_parts(b)))
        .ok_or_else(|| KeychainError::Other("cannot determine installed Weixin version".into()))
}

fn newest_version_dir(root: &Path) -> Option<String> {
    std::fs::read_dir(root)
        .ok()?
        .flatten()
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| version_parts(name).len() >= 3)
        .max_by(|a, b| version_parts(a).cmp(&version_parts(b)))
}

fn version_parts(version: &str) -> Vec<u32> {
    version
        .split('.')
        .map(str::parse::<u32>)
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_default()
}

pub fn find_xwechat_files_root(home: &Path) -> Option<PathBuf> {
    if let Some(value) = std::env::var_os("WX_CLI_WECHAT_DATA_DIR") {
        let configured = PathBuf::from(value);
        return configured.join("all_users").is_dir().then_some(configured);
    }

    let mut candidates = Vec::new();
    candidates.push(home.join("Documents").join("xwechat_files"));
    candidates.push(home.join("xwechat_files"));
    for letter in b'C'..=b'Z' {
        let drive = format!("{}:/", letter as char);
        candidates.push(PathBuf::from(&drive).join("xwechat_files"));
        candidates.push(
            PathBuf::from(&drive)
                .join("Documents")
                .join("xwechat_files"),
        );
    }
    candidates
        .into_iter()
        .find(|candidate| candidate.join("all_users").is_dir())
}

pub fn preflight_checks() -> Vec<PreflightCheck> {
    let process = find_weixin_pid();
    let process_check = PreflightCheck {
        name: "Weixin process",
        passed: process.is_ok(),
        detail: process
            .as_ref()
            .map(|pid| format!("Weixin is running (pid {pid})"))
            .unwrap_or_else(|err| err.to_string()),
        fix_cmd: None,
    };
    let version = installed_weixin_version();
    let version_check = PreflightCheck {
        name: "Weixin version",
        passed: version.is_ok(),
        detail: version.unwrap_or_else(|err| err.to_string()),
        fix_cmd: None,
    };
    let data_root = wx_paths::AppPaths::new()
        .ok()
        .and_then(|paths| find_xwechat_files_root(paths.home()));
    let data_check = PreflightCheck {
        name: "WeChat data",
        passed: data_root.is_some(),
        detail: data_root
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "xwechat_files not found".into()),
        fix_cmd: Some("set WX_CLI_WECHAT_DATA_DIR=<path-to-xwechat_files>".into()),
    };
    let memory_check = match process {
        Ok(pid) => match WindowsMemoryReader::open(pid) {
            Ok(_) => PreflightCheck {
                name: "Process memory",
                passed: true,
                detail: "Weixin process memory is readable".into(),
                fix_cmd: None,
            },
            Err(err) => PreflightCheck {
                name: "Process memory",
                passed: false,
                detail: err.to_string(),
                fix_cmd: Some("run wx-cli from an elevated terminal if access is denied".into()),
            },
        },
        Err(err) => PreflightCheck {
            name: "Process memory",
            passed: false,
            detail: err.to_string(),
            fix_cmd: None,
        },
    };
    vec![process_check, version_check, data_check, memory_check]
}

pub struct WindowsMemoryReader {
    handle: HANDLE,
}

impl WindowsMemoryReader {
    pub fn open(pid: u32) -> Result<Self, KeychainError> {
        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid);
            if handle.is_null() {
                return Err(KeychainError::Other(format!(
                    "OpenProcess({pid}) failed: {}",
                    std::io::Error::last_os_error()
                )));
            }
            Ok(Self { handle })
        }
    }
}

impl Drop for WindowsMemoryReader {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.handle);
        }
    }
}

impl MemoryReader for WindowsMemoryReader {
    fn rw_regions(&self) -> Result<Vec<MemRegion>, KeychainError> {
        let mut regions = Vec::new();
        let mut address = 0usize;
        loop {
            let mut info: MEMORY_BASIC_INFORMATION = unsafe { zeroed() };
            let queried = unsafe {
                VirtualQueryEx(
                    self.handle,
                    address as *const _,
                    &mut info,
                    size_of::<MEMORY_BASIC_INFORMATION>(),
                )
            };
            if queried == 0 {
                break;
            }

            let protection = info.Protect;
            let readable = matches!(
                protection & 0xff,
                PAGE_READONLY
                    | PAGE_READWRITE
                    | PAGE_WRITECOPY
                    | PAGE_EXECUTE_READ
                    | PAGE_EXECUTE_READWRITE
                    | PAGE_EXECUTE_WRITECOPY
            );
            let guarded = protection & (PAGE_GUARD | PAGE_NOACCESS) != 0;
            let start = info.BaseAddress as usize;
            let end = start.saturating_add(info.RegionSize);
            if info.State == MEM_COMMIT && readable && !guarded && end > start {
                regions.push(MemRegion {
                    start: start as u64,
                    end: end as u64,
                });
            }
            if end <= address {
                break;
            }
            address = end;
        }
        Ok(regions)
    }

    fn read_bytes(&self, addr: u64, len: usize) -> Result<Vec<u8>, KeychainError> {
        let mut data = vec![0u8; len];
        let mut read = 0usize;
        let ok = unsafe {
            ReadProcessMemory(
                self.handle,
                addr as *const _,
                data.as_mut_ptr().cast(),
                len,
                &mut read,
            )
        };
        if ok == 0 || read == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        data.truncate(read);
        Ok(data)
    }
}

pub fn capture_key_windows(
    pid: u32,
    accounts: &[AccountDirInfo],
    params: &wx_decrypt::CryptoParams,
) -> Result<Vec<MemoryCaptureResult>, KeychainError> {
    let reader = WindowsMemoryReader::open(pid)?;
    mach_vm::capture_keys_with_reader(reader, accounts, params)
}

pub fn capture_keys_windows(
    pids: &[u32],
    accounts: &[AccountDirInfo],
    params: &wx_decrypt::CryptoParams,
) -> Result<Vec<MemoryCaptureResult>, KeychainError> {
    let mut by_account: HashMap<String, (AccountDirInfo, Vec<EncKeyPair>)> = HashMap::new();

    for &pid in pids {
        let Ok(results) = capture_key_windows(pid, accounts, params) else {
            continue;
        };
        for result in results {
            let KeyMaterial::EncKeys(pairs) = result.key_material else {
                continue;
            };
            let entry = by_account
                .entry(result.matched_account.account_id.clone())
                .or_insert_with(|| (result.matched_account, Vec::new()));
            entry.1.extend(pairs);
        }
    }

    let mut results = Vec::new();
    for (_, (account, mut pairs)) in by_account {
        pairs.sort_by(|a, b| a.salt.cmp(&b.salt).then_with(|| a.key.cmp(&b.key)));
        pairs.dedup();
        results.push(MemoryCaptureResult {
            key_material: KeyMaterial::EncKeys(pairs),
            matched_account: account,
        });
    }
    results.sort_by(|a, b| {
        a.matched_account
            .account_id
            .cmp(&b.matched_account.account_id)
    });

    if results.is_empty() {
        Err(KeychainError::NoKeysFound)
    } else {
        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_parsing_is_numeric() {
        assert!(version_parts("4.1.11.24") > version_parts("4.1.9.99"));
        assert!(version_parts("not-a-version").is_empty());
    }

    #[test]
    fn explicit_data_root_wins() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("all_users")).unwrap();
        std::env::set_var("WX_CLI_WECHAT_DATA_DIR", tmp.path());
        assert_eq!(
            find_xwechat_files_root(Path::new("C:/missing")),
            Some(tmp.path().to_path_buf())
        );
        std::env::remove_var("WX_CLI_WECHAT_DATA_DIR");
    }
}
