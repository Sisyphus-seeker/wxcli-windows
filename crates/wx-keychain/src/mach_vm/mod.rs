pub mod pattern;
pub mod reader;
pub mod scanner;

#[cfg(target_os = "macos")]
pub mod mach_reader;

pub use pattern::{scan_chunk, FoundKey};
pub use reader::{MemRegion, MemoryReader};
pub use scanner::{MemoryScanner, ScanResult};

#[cfg(target_os = "macos")]
pub use mach_reader::MachVmReader;

use crate::error::KeychainError;
use crate::process::AccountDirInfo;
use std::collections::HashMap;
use std::path::PathBuf;
use wx_decrypt::{EncKeyPair, KeyMaterial};

/// Result of a successful process-memory key capture for one account.
#[derive(Debug, Clone)]
pub struct MemoryCaptureResult {
    pub key_material: KeyMaterial,
    pub matched_account: AccountDirInfo,
}

#[cfg(target_os = "macos")]
pub type MachCaptureResult = MemoryCaptureResult;

/// Recursively find all `.db` files under a directory.
pub(crate) fn find_db_files(dir: &std::path::Path) -> Vec<PathBuf> {
    let mut result = Vec::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return result,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            result.extend(find_db_files(&path));
        } else if path.extension().is_some_and(|e| e == "db") {
            result.push(path);
        }
    }
    result
}

/// Scan WeChat process memory for pre-derived encryption keys.
///
/// Attaches to the process via `task_for_pid`, enumerates RW regions, scans for
/// `x'<enc_key><salt>'` patterns, matches each candidate's salt against the
/// provided account DBs, and HMAC-validates before returning.
#[cfg(target_os = "macos")]
pub fn capture_key_mach(
    pid: u32,
    accounts: &[AccountDirInfo],
    params: &wx_decrypt::CryptoParams,
) -> Result<Vec<MachCaptureResult>, KeychainError> {
    let reader = MachVmReader::attach(pid)?;
    capture_keys_with_reader(reader, accounts, params)
}

/// Scan a process through a platform-specific reader and aggregate validated keys by account.
pub fn capture_keys_with_reader<R: MemoryReader>(
    reader: R,
    accounts: &[AccountDirInfo],
    params: &wx_decrypt::CryptoParams,
) -> Result<Vec<MemoryCaptureResult>, KeychainError> {
    // Collect (salt, db_path) pairs for ALL candidate DBs across all accounts.
    let mut db_salts: Vec<([u8; 16], PathBuf)> = Vec::new();
    for account in accounts {
        let db_storage = account.data_dir.join("db_storage");
        if !db_storage.exists() {
            continue;
        }

        for db_path in find_db_files(&db_storage) {
            if let Ok(salt) = wx_decrypt::read_db_salt(&db_path) {
                db_salts.push((salt, db_path));
            }
        }
    }

    if db_salts.is_empty() {
        return Err(KeychainError::NoKeysFound);
    }

    let scanner = MemoryScanner::new(reader);
    let db_salt_refs: Vec<([u8; 16], &std::path::Path)> = db_salts
        .iter()
        .map(|(salt, path)| (*salt, path.as_path()))
        .collect();
    let scan_results = scanner.scan(&db_salt_refs, params)?;

    if scan_results.is_empty() {
        return Err(KeychainError::NoKeysFound);
    }

    // Aggregate scan results by account: collect all (enc_key, salt) pairs per account.
    let mut account_pairs: HashMap<String, (AccountDirInfo, Vec<EncKeyPair>)> = HashMap::new();
    for sr in scan_results {
        if let Some(account) = accounts.iter().find(|a| {
            let db_storage = a.data_dir.join("db_storage");
            sr.db_path.starts_with(&db_storage)
        }) {
            let entry = account_pairs
                .entry(account.account_id.clone())
                .or_insert_with(|| (account.clone(), Vec::new()));
            entry.1.push(EncKeyPair {
                key: sr.enc_key,
                salt: sr.salt,
            });
        }
    }

    if account_pairs.is_empty() {
        return Err(KeychainError::NoKeysFound);
    }

    let mut results: Vec<MemoryCaptureResult> = Vec::new();
    for (_account_id, (account, mut pairs)) in account_pairs {
        // Deduplicate by (salt, key) and sort for stable output.
        pairs.sort_by(|a, b| a.salt.cmp(&b.salt).then_with(|| a.key.cmp(&b.key)));
        pairs.dedup();

        if pairs.is_empty() {
            continue;
        }

        // Always use EncKeys as the canonical format, even for a single pair.
        results.push(MemoryCaptureResult {
            key_material: KeyMaterial::EncKeys(pairs),
            matched_account: account,
        });
    }

    if results.is_empty() {
        return Err(KeychainError::NoKeysFound);
    }

    // Sort by account_id for stable cross-account output order.
    results.sort_by(|a, b| {
        a.matched_account
            .account_id
            .cmp(&b.matched_account.account_id)
    });

    Ok(results)
}
