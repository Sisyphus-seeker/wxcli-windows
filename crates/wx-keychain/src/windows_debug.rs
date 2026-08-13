use std::collections::{HashMap, HashSet};
use std::mem::{size_of, zeroed};
use std::os::windows::ffi::OsStrExt;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    CloseHandle, DBG_CONTINUE, DBG_EXCEPTION_NOT_HANDLED, EXCEPTION_BREAKPOINT,
    EXCEPTION_SINGLE_STEP, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Cryptography::{
    BCryptCloseAlgorithmProvider, BCryptDeriveKeyPBKDF2, BCryptOpenAlgorithmProvider,
    BCRYPT_ALG_HANDLE_HMAC_FLAG, BCRYPT_SHA1_ALGORITHM, BCRYPT_SHA256_ALGORITHM,
};
use windows_sys::Win32::Storage::FileSystem::GetFinalPathNameByHandleW;
use windows_sys::Win32::System::Diagnostics::Debug::{
    ContinueDebugEvent, DebugActiveProcess, DebugActiveProcessStop, DebugBreakProcess,
    DebugSetProcessKillOnExit, FlushInstructionCache, GetThreadContext, ReadProcessMemory,
    SetThreadContext, WaitForDebugEvent, WriteProcessMemory, CONTEXT, CONTEXT_ALL_AMD64,
    CREATE_PROCESS_DEBUG_EVENT, DEBUG_EVENT, EXCEPTION_DEBUG_EVENT, EXIT_PROCESS_DEBUG_EVENT,
    LOAD_DLL_DEBUG_EVENT,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W, TH32CS_SNAPMODULE,
    TH32CS_SNAPMODULE32,
};
use windows_sys::Win32::System::Memory::{
    VirtualProtectEx, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS,
};
use windows_sys::Win32::System::Threading::{
    CreateProcessW, OpenProcess, OpenThread, CREATE_UNICODE_ENVIRONMENT, DEBUG_PROCESS,
    PROCESS_INFORMATION, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ,
    PROCESS_VM_WRITE, STARTUPINFOW, THREAD_GET_CONTEXT, THREAD_SET_CONTEXT,
};

use crate::error::KeychainError;
use crate::mach_vm::{self, MemoryCaptureResult, MemoryReader};
use crate::process::AccountDirInfo;
use crate::windows::{installed_weixin_version, WindowsMemoryReader};
use wx_decrypt::{CryptoParams, EncKeyPair, KeyMaterial};

const SUPPORTED_DEBUG_VERSION: &str = "4.1.11.24";
const WEIXIN_DLL_NAME: &str = "Weixin.dll";
const KEY_UNMASKED_BREAKPOINT_RVA: u64 = 0x0336_A1E7;
const TRAP_FLAG: u32 = 0x100;
const KEY_MASK: [u8; 32] = [
    0x55, 0xE8, 0x9C, 0x9F, 0xCC, 0x23, 0xE3, 0x38, 0x2F, 0x46, 0x54, 0xD4, 0xF9, 0xD7, 0x23, 0x7E,
    0x4A, 0xCC, 0x82, 0xE5, 0xCA, 0xD1, 0x41, 0x2C, 0x7F, 0xC6, 0x59, 0xCB, 0x2A, 0x33, 0xAD, 0xAF,
];

struct DbTarget {
    account_index: usize,
    salt: [u8; 16],
    first_page: Vec<u8>,
}

#[derive(Default)]
struct CaptureStats {
    breakpoint_hits: usize,
    readable_salts: usize,
    matched_salts: usize,
    readable_keys: usize,
    parsed_patterns: usize,
}

struct ProcessDebugState {
    handle: HANDLE,
    breakpoint: Option<BreakpointState>,
}

struct BreakpointState {
    address: u64,
    original: u8,
    installed: bool,
}

pub fn capture_keys_windows_debug(
    pids: &[u32],
    accounts: &[AccountDirInfo],
    params: &CryptoParams,
    timeout: Duration,
) -> Result<Vec<MemoryCaptureResult>, KeychainError> {
    let version = installed_weixin_version()?;
    if version != SUPPORTED_DEBUG_VERSION {
        return Err(KeychainError::Other(format!(
            "dynamic capture supports Weixin {SUPPORTED_DEBUG_VERSION}, found {version}"
        )));
    }

    let targets = collect_targets(accounts, params);
    if targets.is_empty() {
        return Err(KeychainError::NoKeysFound);
    }

    let mut ranked_pids = pids
        .iter()
        .filter_map(|&pid| {
            let reader = WindowsMemoryReader::open(pid).ok()?;
            let region_count = reader.rw_regions().ok()?.len();
            Some((region_count, pid))
        })
        .collect::<Vec<_>>();
    ranked_pids.sort_unstable_by(|a, b| b.cmp(a));
    if ranked_pids.is_empty() {
        return Err(KeychainError::NoKeysFound);
    }

    // Weixin 4.x is a multi-process application. The process with the largest
    // readable address space is not necessarily the process that performs
    // database key derivation, so try every readable candidate instead of
    // failing after the first heuristic choice.
    let started = Instant::now();
    let per_process = timeout
        .checked_div(ranked_pids.len() as u32)
        .unwrap_or(timeout)
        .max(Duration::from_secs(1));
    let mut captured = Vec::new();
    let mut errors = Vec::new();
    for (_, pid) in ranked_pids {
        let elapsed = started.elapsed();
        let Some(remaining) = timeout.checked_sub(elapsed) else {
            break;
        };
        if remaining.is_zero() {
            break;
        }

        eprintln!("Waiting for Weixin database activity (pid {pid})...");
        match capture_process(pid, &targets, params, per_process.min(remaining)) {
            Ok(mut keys) => captured.append(&mut keys),
            Err(error) => {
                eprintln!("  pid {pid} capture skipped: {error}");
                errors.push(format!("pid {pid}: {error}"));
            }
        }
    }

    captured.sort_unstable_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    captured.dedup();
    if captured.is_empty() && !errors.is_empty() {
        return Err(KeychainError::Other(format!(
            "no valid enc_key found in Weixin process memory; tried {} process{}:\n{}",
            errors.len(),
            if errors.len() == 1 { "" } else { "es" },
            errors.join("\n")
        )));
    }
    aggregate_results(captured, &targets, accounts)
}

pub fn launch_and_capture_keys_windows_debug(
    accounts: &[AccountDirInfo],
    params: &CryptoParams,
    timeout: Duration,
) -> Result<Vec<MemoryCaptureResult>, KeychainError> {
    let version = installed_weixin_version()?;
    if version != SUPPORTED_DEBUG_VERSION {
        return Err(KeychainError::Other(format!(
            "dynamic launch supports Weixin {SUPPORTED_DEBUG_VERSION}, found {version}"
        )));
    }

    let targets = collect_targets(accounts, params);
    if targets.is_empty() {
        return Err(KeychainError::NoKeysFound);
    }
    let executable = find_weixin_executable()?;
    eprintln!("Launching Weixin with startup key capture...");
    let captured = unsafe { capture_launched_process(&executable, &targets, params, timeout)? };
    aggregate_results(captured, &targets, accounts)
}

unsafe fn capture_launched_process(
    executable: &std::path::Path,
    targets: &[DbTarget],
    params: &CryptoParams,
    timeout: Duration,
) -> Result<Vec<(usize, [u8; 32])>, KeychainError> {
    let executable_wide = wide_null(executable.as_os_str());
    let working_directory_wide = executable
        .parent()
        .map(|path| wide_null(path.as_os_str()))
        .unwrap_or_default();
    let mut startup_info: STARTUPINFOW = unsafe { zeroed() };
    startup_info.cb = size_of::<STARTUPINFOW>() as u32;
    let mut process_info: PROCESS_INFORMATION = unsafe { zeroed() };
    let created = unsafe {
        CreateProcessW(
            executable_wide.as_ptr(),
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            DEBUG_PROCESS | CREATE_UNICODE_ENVIRONMENT,
            std::ptr::null(),
            if working_directory_wide.is_empty() {
                std::ptr::null()
            } else {
                working_directory_wide.as_ptr()
            },
            &startup_info,
            &mut process_info,
        )
    };
    if created == 0 {
        return Err(last_error("CreateProcessW(Weixin)"));
    }
    unsafe {
        CloseHandle(process_info.hThread);
        CloseHandle(process_info.hProcess);
        DebugSetProcessKillOnExit(0);
    }

    let mut processes: HashMap<u32, ProcessDebugState> = HashMap::new();
    let mut stepping_threads: HashSet<(u32, u32)> = HashSet::new();
    let mut captured = Vec::new();
    let mut stats = CaptureStats::default();
    let started = Instant::now();

    while started.elapsed() < timeout {
        let mut event: DEBUG_EVENT = unsafe { zeroed() };
        if unsafe { WaitForDebugEvent(&mut event, 250) } == 0 {
            continue;
        }

        let mut continue_status = DBG_CONTINUE;
        match event.dwDebugEventCode {
            CREATE_PROCESS_DEBUG_EVENT => {
                let info = unsafe { event.u.CreateProcessInfo };
                processes.insert(
                    event.dwProcessId,
                    ProcessDebugState {
                        handle: info.hProcess,
                        breakpoint: None,
                    },
                );
                close_if_valid(info.hFile);
            }
            LOAD_DLL_DEBUG_EVENT => {
                let info = unsafe { event.u.LoadDll };
                let is_weixin_dll = path_from_handle(info.hFile)
                    .and_then(|path| path.file_name().map(|name| name.to_owned()))
                    .is_some_and(|name| {
                        name.to_string_lossy().eq_ignore_ascii_case(WEIXIN_DLL_NAME)
                    });
                if is_weixin_dll {
                    if let Some(state) = processes.get_mut(&event.dwProcessId) {
                        let address = info.lpBaseOfDll as u64 + KEY_UNMASKED_BREAKPOINT_RVA;
                        if let Ok(original) = read_exact(state.handle, address, 1) {
                            if write_byte(state.handle, address, 0xCC).is_ok() {
                                state.breakpoint = Some(BreakpointState {
                                    address,
                                    original: original[0],
                                    installed: true,
                                });
                            }
                        }
                    }
                }
                close_if_valid(info.hFile);
            }
            EXCEPTION_DEBUG_EVENT => {
                let exception = unsafe { event.u.Exception };
                let code = exception.ExceptionRecord.ExceptionCode;
                let address = exception.ExceptionRecord.ExceptionAddress as u64;
                if let Some(state) = processes.get_mut(&event.dwProcessId) {
                    let is_our_breakpoint = state.breakpoint.as_ref().is_some_and(|breakpoint| {
                        breakpoint.installed && breakpoint.address == address
                    });
                    if code == EXCEPTION_BREAKPOINT && is_our_breakpoint {
                        if let (Some(breakpoint), Ok(mut context)) =
                            (state.breakpoint.as_mut(), thread_context(event.dwThreadId))
                        {
                            stats.breakpoint_hits += 1;
                            capture_context(
                                state.handle,
                                &context,
                                targets,
                                params,
                                &mut captured,
                                &mut stats,
                            );
                            let _ =
                                write_byte(state.handle, breakpoint.address, breakpoint.original);
                            breakpoint.installed = false;
                            context.Rip = breakpoint.address;
                            context.EFlags |= TRAP_FLAG;
                            if set_thread_context(event.dwThreadId, &context).is_ok() {
                                stepping_threads.insert((event.dwProcessId, event.dwThreadId));
                            }
                        }
                    } else if code == EXCEPTION_SINGLE_STEP
                        && stepping_threads.remove(&(event.dwProcessId, event.dwThreadId))
                    {
                        if let Ok(mut context) = thread_context(event.dwThreadId) {
                            context.EFlags &= !TRAP_FLAG;
                            let _ = set_thread_context(event.dwThreadId, &context);
                        }
                        if let Some(breakpoint) = state.breakpoint.as_mut() {
                            if write_byte(state.handle, breakpoint.address, 0xCC).is_ok() {
                                breakpoint.installed = true;
                            }
                        }
                    } else if code != EXCEPTION_BREAKPOINT {
                        continue_status = DBG_EXCEPTION_NOT_HANDLED;
                    }
                }
            }
            EXIT_PROCESS_DEBUG_EVENT => {
                if let Some(state) = processes.remove(&event.dwProcessId) {
                    close_if_valid(state.handle);
                }
            }
            _ => {}
        }

        unsafe { ContinueDebugEvent(event.dwProcessId, event.dwThreadId, continue_status) };
    }

    for (&pid, state) in &mut processes {
        if let Some(breakpoint) = state.breakpoint.as_mut() {
            if breakpoint.installed {
                let _ = write_byte(state.handle, breakpoint.address, breakpoint.original);
                breakpoint.installed = false;
            }
        }
        unsafe { DebugActiveProcessStop(pid) };
        close_if_valid(state.handle);
    }

    if std::env::var_os("WX_CLI_SCAN_DIAGNOSTICS").is_some() {
        eprintln!(
            "scan diagnostics: startup capture hit {} breakpoints, read {}/{} salts and {} key buffers, parsed {} protected patterns, validated {} database keys",
            stats.breakpoint_hits,
            stats.readable_salts,
            stats.matched_salts,
            stats.readable_keys,
            stats.parsed_patterns,
            captured.len(),
        );
    }
    captured.sort_unstable_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    captured.dedup();
    Ok(captured)
}

fn collect_targets(accounts: &[AccountDirInfo], params: &CryptoParams) -> Vec<DbTarget> {
    let mut targets = Vec::new();
    for (account_index, account) in accounts.iter().enumerate() {
        let db_storage = account.data_dir.join("db_storage");
        for path in mach_vm::find_db_files(&db_storage) {
            let Ok(data) = wx_decrypt::read_prefix_shared(&path, params.page_size) else {
                continue;
            };
            let Ok(salt) = data[..params.salt_size].try_into() else {
                continue;
            };
            if targets.iter().any(|target: &DbTarget| target.salt == salt) {
                continue;
            }
            targets.push(DbTarget {
                account_index,
                salt,
                first_page: data[..params.page_size].to_vec(),
            });
        }
    }
    targets
}

fn aggregate_results(
    captured: Vec<(usize, [u8; 32])>,
    targets: &[DbTarget],
    accounts: &[AccountDirInfo],
) -> Result<Vec<MemoryCaptureResult>, KeychainError> {
    let mut by_account: HashMap<usize, Vec<EncKeyPair>> = HashMap::new();
    for (target_index, key) in captured {
        let target = &targets[target_index];
        by_account
            .entry(target.account_index)
            .or_default()
            .push(EncKeyPair {
                key,
                salt: target.salt,
            });
    }

    let mut results = Vec::new();
    for (account_index, mut pairs) in by_account {
        pairs.sort_by(|a, b| a.salt.cmp(&b.salt).then_with(|| a.key.cmp(&b.key)));
        pairs.dedup();
        results.push(MemoryCaptureResult {
            key_material: KeyMaterial::EncKeys(pairs),
            matched_account: accounts[account_index].clone(),
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

fn capture_process(
    pid: u32,
    targets: &[DbTarget],
    params: &CryptoParams,
    timeout: Duration,
) -> Result<Vec<(usize, [u8; 32])>, KeychainError> {
    let module_base = find_module_base(pid, WEIXIN_DLL_NAME)?;
    let breakpoint_address = module_base + KEY_UNMASKED_BREAKPOINT_RVA;
    let process = unsafe {
        OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
            0,
            pid,
        )
    };
    if process.is_null() {
        return Err(last_error(format!("OpenProcess({pid})")));
    }

    let result = unsafe {
        capture_attached_process(process, pid, breakpoint_address, targets, params, timeout)
    };
    unsafe { CloseHandle(process) };
    result
}

unsafe fn capture_attached_process(
    process: HANDLE,
    pid: u32,
    breakpoint_address: u64,
    targets: &[DbTarget],
    params: &CryptoParams,
    timeout: Duration,
) -> Result<Vec<(usize, [u8; 32])>, KeychainError> {
    if unsafe { DebugActiveProcess(pid) } == 0 {
        return Err(last_error(format!("DebugActiveProcess({pid})")));
    }
    unsafe { DebugSetProcessKillOnExit(0) };

    let original = match read_exact(process, breakpoint_address, 1) {
        Ok(bytes) => bytes[0],
        Err(err) => {
            unsafe { DebugActiveProcessStop(pid) };
            return Err(err);
        }
    };
    let mut breakpoint_installed = false;
    let mut stepping_thread = None;
    let mut stop_requested = false;
    let mut captured = Vec::new();
    let mut stats = CaptureStats::default();
    let started = Instant::now();

    loop {
        if !stop_requested && started.elapsed() >= timeout {
            if unsafe { DebugBreakProcess(process) } == 0 {
                break;
            }
            stop_requested = true;
        }

        let mut event: DEBUG_EVENT = unsafe { zeroed() };
        if unsafe { WaitForDebugEvent(&mut event, 250) } == 0 {
            continue;
        }

        if !breakpoint_installed && stepping_thread.is_none() && !stop_requested {
            if write_byte(process, breakpoint_address, 0xCC).is_err() {
                unsafe { ContinueDebugEvent(event.dwProcessId, event.dwThreadId, DBG_CONTINUE) };
                break;
            }
            breakpoint_installed = true;
        }

        let mut continue_status = DBG_CONTINUE;
        let mut should_detach = false;
        if event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT {
            let exception = unsafe { event.u.Exception };
            let code = exception.ExceptionRecord.ExceptionCode;
            let address = exception.ExceptionRecord.ExceptionAddress as u64;

            if code == EXCEPTION_BREAKPOINT && address == breakpoint_address {
                if let Ok(mut context) = thread_context(event.dwThreadId) {
                    stats.breakpoint_hits += 1;
                    capture_context(
                        process,
                        &context,
                        targets,
                        params,
                        &mut captured,
                        &mut stats,
                    );
                    let _ = write_byte(process, breakpoint_address, original);
                    breakpoint_installed = false;
                    context.Rip = breakpoint_address;
                    context.EFlags |= TRAP_FLAG;
                    if set_thread_context(event.dwThreadId, &context).is_ok() {
                        stepping_thread = Some(event.dwThreadId);
                    } else {
                        should_detach = true;
                    }
                } else {
                    should_detach = true;
                }
            } else if code == EXCEPTION_SINGLE_STEP && stepping_thread == Some(event.dwThreadId) {
                if let Ok(mut context) = thread_context(event.dwThreadId) {
                    context.EFlags &= !TRAP_FLAG;
                    let _ = set_thread_context(event.dwThreadId, &context);
                }
                stepping_thread = None;
                if !stop_requested && write_byte(process, breakpoint_address, 0xCC).is_ok() {
                    breakpoint_installed = true;
                }
            } else if stop_requested && code == EXCEPTION_BREAKPOINT {
                should_detach = true;
            } else {
                continue_status = DBG_EXCEPTION_NOT_HANDLED;
            }
        }

        if should_detach && breakpoint_installed {
            let _ = write_byte(process, breakpoint_address, original);
            breakpoint_installed = false;
        }
        unsafe { ContinueDebugEvent(event.dwProcessId, event.dwThreadId, continue_status) };
        if should_detach {
            break;
        }
    }

    if breakpoint_installed {
        let _ = write_byte(process, breakpoint_address, original);
    }
    unsafe { DebugActiveProcessStop(pid) };

    if std::env::var_os("WX_CLI_SCAN_DIAGNOSTICS").is_some() {
        eprintln!(
            "scan diagnostics: dynamic capture hit {} breakpoints, read {}/{} salts and {} key buffers, parsed {} protected patterns, validated {} database keys",
            stats.breakpoint_hits,
            stats.readable_salts,
            stats.matched_salts,
            stats.readable_keys,
            stats.parsed_patterns,
            captured.len(),
        );
    }
    captured.sort_unstable_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    captured.dedup();
    Ok(captured)
}

fn capture_context(
    process: HANDLE,
    context: &CONTEXT,
    targets: &[DbTarget],
    params: &CryptoParams,
    captured: &mut Vec<(usize, [u8; 32])>,
    stats: &mut CaptureStats,
) {
    let Ok(salt_pointer_bytes) = read_exact(process, context.Rcx + 0x48, 8) else {
        return;
    };
    let salt_pointer = u64::from_le_bytes(salt_pointer_bytes.try_into().expect("salt pointer"));
    let Ok(salt_bytes) = read_exact(process, salt_pointer, 16) else {
        return;
    };
    let Ok(salt) = <[u8; 16]>::try_from(salt_bytes) else {
        return;
    };
    stats.readable_salts += 1;
    let Some((target_index, target)) = targets
        .iter()
        .enumerate()
        .find(|(_, target)| target.salt == salt)
    else {
        return;
    };
    stats.matched_salts += 1;
    let key_length = context.Rsi as usize;
    if !(32..=128).contains(&key_length) {
        return;
    }
    let Ok(key_bytes) = read_exact(process, context.R11, key_length) else {
        return;
    };
    stats.readable_keys += 1;

    for value in [key_bytes.clone(), unmask_key_buffer(&key_bytes)] {
        for found in mach_vm::scan_chunk(&value) {
            stats.parsed_patterns += 1;
            let hex_password = hex::encode(found.enc_key);
            let mut candidates = vec![
                found.enc_key,
                wx_decrypt::kdf::derive_enc_key(&found.enc_key, &target.salt, params),
            ];
            for password in [found.enc_key.as_slice(), hex_password.as_bytes()] {
                for algorithm in [BCRYPT_SHA1_ALGORITHM, BCRYPT_SHA256_ALGORITHM] {
                    if let Some(candidate) =
                        derive_windows_pbkdf2(password, &target.salt, 256_000, algorithm)
                    {
                        candidates.push(candidate);
                    }
                }
            }
            candidates.sort_unstable();
            candidates.dedup();
            for candidate in candidates {
                if validate_candidate(target, &candidate, params) {
                    captured.push((target_index, candidate));
                    return;
                }
            }
        }
    }

    if key_bytes.len() >= 32 {
        let key: [u8; 32] = key_bytes[..32].try_into().expect("key buffer");
        let unmasked = std::array::from_fn(|index| key[index] ^ KEY_MASK[index]);
        for candidate in [key, unmasked] {
            if validate_candidate(target, &candidate, params) {
                captured.push((target_index, candidate));
                return;
            }
        }
    }
}

fn unmask_key_buffer(bytes: &[u8]) -> Vec<u8> {
    bytes
        .iter()
        .enumerate()
        .map(|(index, byte)| byte ^ KEY_MASK[index & 31])
        .collect()
}

fn validate_candidate(target: &DbTarget, candidate: &[u8; 32], params: &CryptoParams) -> bool {
    wx_decrypt::validate_enc_key_header_reserves(
        &target.first_page,
        candidate,
        &[params.reserve, 48, 64],
    )
    .is_some()
        || wx_decrypt::validate_enc_key(&target.first_page, candidate, &target.salt, params)
}

fn derive_windows_pbkdf2(
    password: &[u8],
    salt: &[u8],
    iterations: u64,
    algorithm: *const u16,
) -> Option<[u8; 32]> {
    let mut handle = std::ptr::null_mut();
    let opened = unsafe {
        BCryptOpenAlgorithmProvider(
            &mut handle,
            algorithm,
            std::ptr::null(),
            BCRYPT_ALG_HANDLE_HMAC_FLAG,
        )
    };
    if opened < 0 {
        return None;
    }

    let mut output = [0u8; 32];
    let status = unsafe {
        BCryptDeriveKeyPBKDF2(
            handle,
            password.as_ptr(),
            password.len() as u32,
            salt.as_ptr(),
            salt.len() as u32,
            iterations,
            output.as_mut_ptr(),
            output.len() as u32,
            0,
        )
    };
    unsafe { BCryptCloseAlgorithmProvider(handle, 0) };
    (status >= 0).then_some(output)
}

fn find_weixin_executable() -> Result<PathBuf, KeychainError> {
    let mut candidates = Vec::new();
    if let Some(program_files) = std::env::var_os("ProgramFiles") {
        candidates.push(
            PathBuf::from(program_files)
                .join("Tencent")
                .join("Weixin")
                .join("Weixin.exe"),
        );
    }
    candidates.push(PathBuf::from(r"C:\Program Files\Tencent\Weixin\Weixin.exe"));
    candidates
        .into_iter()
        .find(|path| path.is_file())
        .ok_or_else(|| KeychainError::Other("Weixin.exe not found".into()))
}

fn wide_null(value: &std::ffi::OsStr) -> Vec<u16> {
    value.encode_wide().chain(std::iter::once(0)).collect()
}

fn path_from_handle(handle: HANDLE) -> Option<PathBuf> {
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return None;
    }
    let mut buffer = vec![0u16; 1024];
    let length =
        unsafe { GetFinalPathNameByHandleW(handle, buffer.as_mut_ptr(), buffer.len() as u32, 0) }
            as usize;
    if length == 0 || length >= buffer.len() {
        return None;
    }
    buffer.truncate(length);
    Some(PathBuf::from(String::from_utf16_lossy(&buffer)))
}

fn close_if_valid(handle: HANDLE) {
    if !handle.is_null() && handle != INVALID_HANDLE_VALUE {
        unsafe { CloseHandle(handle) };
    }
}

fn find_module_base(pid: u32, module_name: &str) -> Result<u64, KeychainError> {
    let snapshot =
        unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid) };
    if snapshot == INVALID_HANDLE_VALUE {
        return Err(last_error("CreateToolhelp32Snapshot(modules)"));
    }

    let mut entry: MODULEENTRY32W = unsafe { zeroed() };
    entry.dwSize = size_of::<MODULEENTRY32W>() as u32;
    let mut found = None;
    if unsafe { Module32FirstW(snapshot, &mut entry) } != 0 {
        loop {
            let end = entry
                .szModule
                .iter()
                .position(|&character| character == 0)
                .unwrap_or(entry.szModule.len());
            let name = String::from_utf16_lossy(&entry.szModule[..end]);
            if name.eq_ignore_ascii_case(module_name) {
                found = Some(entry.modBaseAddr as u64);
                break;
            }
            if unsafe { Module32NextW(snapshot, &mut entry) } == 0 {
                break;
            }
        }
    }
    unsafe { CloseHandle(snapshot) };
    found.ok_or_else(|| KeychainError::Other(format!("{module_name} not loaded in pid {pid}")))
}

fn thread_context(thread_id: u32) -> Result<CONTEXT, KeychainError> {
    let thread = unsafe { OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, 0, thread_id) };
    if thread.is_null() {
        return Err(last_error(format!("OpenThread({thread_id})")));
    }
    let mut context: CONTEXT = unsafe { zeroed() };
    context.ContextFlags = CONTEXT_ALL_AMD64;
    let ok = unsafe { GetThreadContext(thread, &mut context) };
    unsafe { CloseHandle(thread) };
    if ok == 0 {
        Err(last_error("GetThreadContext"))
    } else {
        Ok(context)
    }
}

fn set_thread_context(thread_id: u32, context: &CONTEXT) -> Result<(), KeychainError> {
    let thread = unsafe { OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, 0, thread_id) };
    if thread.is_null() {
        return Err(last_error(format!("OpenThread({thread_id})")));
    }
    let ok = unsafe { SetThreadContext(thread, context) };
    unsafe { CloseHandle(thread) };
    if ok == 0 {
        Err(last_error("SetThreadContext"))
    } else {
        Ok(())
    }
}

fn read_exact(process: HANDLE, address: u64, length: usize) -> Result<Vec<u8>, KeychainError> {
    let mut bytes = vec![0u8; length];
    let mut read = 0usize;
    let ok = unsafe {
        ReadProcessMemory(
            process,
            address as *const _,
            bytes.as_mut_ptr().cast(),
            length,
            &mut read,
        )
    };
    if ok == 0 || read != length {
        Err(last_error("ReadProcessMemory"))
    } else {
        Ok(bytes)
    }
}

fn write_byte(process: HANDLE, address: u64, byte: u8) -> Result<(), KeychainError> {
    let mut old_protection: PAGE_PROTECTION_FLAGS = 0;
    if unsafe {
        VirtualProtectEx(
            process,
            address as *const _,
            1,
            PAGE_EXECUTE_READWRITE,
            &mut old_protection,
        )
    } == 0
    {
        return Err(last_error("VirtualProtectEx(enable write)"));
    }

    let mut written = 0usize;
    let write_ok = unsafe {
        WriteProcessMemory(
            process,
            address as *const _,
            (&byte as *const u8).cast(),
            1,
            &mut written,
        )
    };
    unsafe { FlushInstructionCache(process, address as *const _, 1) };
    let mut ignored = 0;
    unsafe {
        VirtualProtectEx(
            process,
            address as *const _,
            1,
            old_protection,
            &mut ignored,
        )
    };
    if write_ok == 0 || written != 1 {
        Err(last_error("WriteProcessMemory"))
    } else {
        Ok(())
    }
}

fn last_error(operation: impl Into<String>) -> KeychainError {
    KeychainError::Other(format!(
        "{} failed: {}",
        operation.into(),
        std::io::Error::last_os_error()
    ))
}
