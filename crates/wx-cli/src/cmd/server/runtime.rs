use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::process::Command;
use std::time::{Duration, Instant};

use serde::de::DeserializeOwned;
use serde::Serialize;
use wx_paths::AppPaths;

use super::types::{ServerHealthPayload, ServerLaunchConfig, ServerRuntimeState};

pub struct ManagementLockGuard {
    lock_file: PathBuf,
}

impl Drop for ManagementLockGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.lock_file);
    }
}

pub fn acquire_management_lock(
    ap: &AppPaths,
) -> Result<ManagementLockGuard, Box<dyn std::error::Error>> {
    ap.ensure_server_dirs()?;
    let lock_file = ap.server_lock_file();

    loop {
        match OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&lock_file)
        {
            Ok(mut file) => {
                writeln!(file, "{}", std::process::id())?;
                return Ok(ManagementLockGuard { lock_file });
            }
            Err(err) if err.kind() == ErrorKind::AlreadyExists => {
                let owner = fs::read_to_string(&lock_file)
                    .ok()
                    .and_then(|s| s.trim().parse::<u32>().ok());
                if owner.is_some_and(pid_is_running) {
                    return Err("another server management operation is in progress".into());
                }
                fs::remove_file(&lock_file)?;
            }
            Err(err) => return Err(err.into()),
        }
    }
}

pub fn save_json<T: Serialize>(path: &Path, value: &T) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let temp = path.with_extension("json.tmp");
    fs::write(&temp, serde_json::to_vec_pretty(value)?)?;
    fs::rename(temp, path)?;
    Ok(())
}

pub fn load_json<T: DeserializeOwned>(
    path: &Path,
) -> Result<Option<T>, Box<dyn std::error::Error>> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err.into()),
    }
}

pub fn load_runtime_state(
    ap: &AppPaths,
) -> Result<Option<ServerRuntimeState>, Box<dyn std::error::Error>> {
    load_json(&ap.server_state_file())
}

pub fn save_runtime_state(
    ap: &AppPaths,
    state: &ServerRuntimeState,
) -> Result<(), Box<dyn std::error::Error>> {
    save_json(&ap.server_state_file(), state)
}

pub fn load_launch_config(
    ap: &AppPaths,
) -> Result<Option<ServerLaunchConfig>, Box<dyn std::error::Error>> {
    load_json(&ap.server_config_file())
}

pub fn save_launch_config(
    ap: &AppPaths,
    config: &ServerLaunchConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    save_json(&ap.server_config_file(), config)
}

pub fn remove_runtime_state(ap: &AppPaths) -> Result<(), Box<dyn std::error::Error>> {
    match fs::remove_file(ap.server_state_file()) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

#[cfg(unix)]
pub fn pid_is_running(pid: u32) -> bool {
    let result = unsafe { libc::kill(pid as i32, 0) };
    if result == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

#[cfg(windows)]
pub fn pid_is_running(pid: u32) -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, STILL_ACTIVE};
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            return false;
        }
        let mut exit_code = 0u32;
        let running =
            GetExitCodeProcess(handle, &mut exit_code) != 0 && exit_code == STILL_ACTIVE as u32;
        CloseHandle(handle);
        running
    }
}

pub fn pid_matches_managed_worker(pid: u32, worker_id: &str) -> bool {
    process_command_line(pid)
        .map(|command| command.contains("server _worker") && command.contains(worker_id))
        .unwrap_or(false)
}

#[cfg(unix)]
pub fn terminate_pid(pid: u32) -> Result<(), Box<dyn std::error::Error>> {
    let result = unsafe { libc::kill(pid as i32, libc::SIGTERM) };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error().into())
    }
}

#[cfg(windows)]
pub fn terminate_pid(pid: u32) -> Result<(), Box<dyn std::error::Error>> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};

    unsafe {
        let handle = OpenProcess(PROCESS_TERMINATE, 0, pid);
        if handle.is_null() {
            return Err(std::io::Error::last_os_error().into());
        }
        let result = TerminateProcess(handle, 0);
        CloseHandle(handle);
        if result == 0 {
            Err(std::io::Error::last_os_error().into())
        } else {
            Ok(())
        }
    }
}

#[cfg(unix)]
fn process_command_line(pid: u32) -> Option<String> {
    let output = Command::new("ps")
        .args(["-o", "command=", "-p", &pid.to_string()])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let command = String::from_utf8(output.stdout).ok()?;
    let trimmed = command.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

#[cfg(windows)]
fn process_command_line(pid: u32) -> Option<String> {
    use std::ffi::c_void;
    use std::mem::size_of;
    use std::ptr;

    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

    const PROCESS_COMMAND_LINE_INFORMATION: u32 = 60;

    #[repr(C)]
    struct UnicodeString {
        length: u16,
        maximum_length: u16,
        buffer: *const u16,
    }

    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtQueryInformationProcess(
            process_handle: *mut c_void,
            process_information_class: u32,
            process_information: *mut c_void,
            process_information_length: u32,
            return_length: *mut u32,
        ) -> i32;
    }

    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            return None;
        }

        let mut required = 0u32;
        NtQueryInformationProcess(
            handle,
            PROCESS_COMMAND_LINE_INFORMATION,
            ptr::null_mut(),
            0,
            &mut required,
        );
        if required < size_of::<UnicodeString>() as u32 {
            CloseHandle(handle);
            return None;
        }

        let mut storage = vec![0u8; required as usize];
        let status = NtQueryInformationProcess(
            handle,
            PROCESS_COMMAND_LINE_INFORMATION,
            storage.as_mut_ptr().cast(),
            required,
            &mut required,
        );
        CloseHandle(handle);
        if status < 0 {
            return None;
        }

        let command = ptr::read_unaligned(storage.as_ptr().cast::<UnicodeString>());
        let byte_len = command.length as usize;
        let storage_start = storage.as_ptr() as usize;
        let storage_end = storage_start.checked_add(storage.len())?;
        let command_start = command.buffer as usize;
        let command_end = command_start.checked_add(byte_len)?;
        if byte_len & 1 != 0
            || command_start < storage_start
            || command_end > storage_end
            || command.maximum_length < command.length
        {
            return None;
        }

        let utf16 = std::slice::from_raw_parts(command.buffer, byte_len / 2);
        Some(String::from_utf16_lossy(utf16))
    }
}

pub fn wait_for_pid_exit(pid: u32, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if !pid_is_running(pid) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    !pid_is_running(pid)
}

pub fn base_url(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("http://[{host}]:{port}")
    } else {
        format!("http://{host}:{port}")
    }
}

pub fn probe_health(
    base_url: &str,
    token: Option<&str>,
) -> Result<ServerHealthPayload, Box<dyn std::error::Error>> {
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_millis(250))
        .timeout_read(Duration::from_millis(750))
        .build();
    let url = format!("{}/api/v1/health", base_url.trim_end_matches('/'));
    let mut request = agent.get(&url);
    if let Some(token) = token {
        request = request.set("Authorization", &format!("Bearer {token}"));
    }
    let response = request.call()?;
    Ok(response.into_json::<ServerHealthPayload>()?)
}

#[derive(Clone, Debug)]
pub struct RuntimeReporter {
    ap: AppPaths,
}

impl RuntimeReporter {
    pub fn new(ap: AppPaths, _config: ServerLaunchConfig) -> Self {
        Self { ap }
    }

    pub fn write_state(&self, state: ServerRuntimeState) -> Result<(), Box<dyn std::error::Error>> {
        save_runtime_state(&self.ap, &state)
    }

    pub fn clear_state(&self) -> Result<(), Box<dyn std::error::Error>> {
        remove_runtime_state(&self.ap)
    }

    pub fn ap(&self) -> &AppPaths {
        &self.ap
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::process_command_line;

    #[test]
    fn reads_current_process_command_line() {
        let command = process_command_line(std::process::id()).expect("read current command line");
        let executable = std::env::current_exe().expect("resolve current executable");
        let file_name = executable
            .file_name()
            .and_then(|name| name.to_str())
            .expect("executable file name");
        assert!(command.contains(file_name), "command line: {command}");
    }
}
