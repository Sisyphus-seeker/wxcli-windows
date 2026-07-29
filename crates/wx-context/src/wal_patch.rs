use std::path::Path;

use wx_decrypt::{dispatch_decrypt_wal, CryptoParams, DecryptError, KeyMaterial};

/// Result of an atomic WAL patch attempt.
///
/// Distinguishes *content* failures (bad data that won't self-heal) from
/// *environment/IO* failures (transient issues that may resolve on retry).
#[derive(Debug)]
pub(crate) enum WalPatchResult {
    /// Successfully patched N frames into the destination DB.
    Patched(usize),
    /// WAL contained no valid frames — destination unchanged.
    NoFrames,
    /// HMAC / decryption / WAL-header failure — the WAL content itself is bad.
    /// Caller should write a failed marker; retrying with the same mtime is pointless.
    ContentFailed(String),
    /// Copy / rename / disk-full or other transient I/O error.
    /// Caller should log a warning but NOT write a failed marker — next run may succeed.
    IoFailed(String),
}

/// Atomically apply encrypted WAL frames to a cached (plaintext) DB.
///
/// Sequence: copy `dst` to tmp -> decrypt WAL frames into tmp -> rename tmp over `dst`.
/// On any failure the tmp file is cleaned up and `dst` is left untouched.
pub(crate) fn apply_wal_patch(
    wal: &Path,
    dst: &Path,
    km: &KeyMaterial,
    params: &CryptoParams,
) -> WalPatchResult {
    let tmp_path = dst.with_extension("db.tmp");

    // Clean up any residual tmp from a previous crash.
    std::fs::remove_file(&tmp_path).ok();

    let result = (|| -> WalPatchResult {
        // Step 1: copy dst -> tmp
        if let Err(e) = std::fs::copy(dst, &tmp_path) {
            return WalPatchResult::IoFailed(format!("copy dst to tmp: {e}"));
        }

        // Step 2: decrypt WAL frames into tmp
        let frame_count = match dispatch_decrypt_wal(wal, &tmp_path, km, params) {
            Ok(n) => n,
            Err(e) => return classify_decrypt_error(e),
        };

        if frame_count == 0 {
            return WalPatchResult::NoFrames;
        }

        // Step 3: atomic rename tmp -> dst
        if let Err(e) = std::fs::rename(&tmp_path, dst) {
            return WalPatchResult::IoFailed(format!("rename tmp to dst: {e}"));
        }

        WalPatchResult::Patched(frame_count)
    })();

    // Ensure tmp is cleaned up on any non-success path.
    // For Patched, the rename already consumed the tmp file.
    // For all other variants (including NoFrames), remove the tmp if it exists.
    if !matches!(result, WalPatchResult::Patched(_)) {
        std::fs::remove_file(&tmp_path).ok();
    }

    result
}

/// Classify a `DecryptError` into either `ContentFailed` or `IoFailed`.
fn classify_decrypt_error(e: DecryptError) -> WalPatchResult {
    match &e {
        // Content failures — the WAL data itself is bad.
        DecryptError::HmacVerificationFailed { .. }
        | DecryptError::AesDecryptFailed { .. }
        | DecryptError::InvalidWalHeader { .. }
        | DecryptError::IncorrectKey => WalPatchResult::ContentFailed(e.to_string()),

        // Environment / transient failures — may self-heal on retry.
        DecryptError::SaltMismatch
        | DecryptError::NoMatchingEncKey
        | DecryptError::Io(_)
        | DecryptError::FileTooSmall { .. }
        | DecryptError::AlreadyDecrypted => WalPatchResult::IoFailed(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Helper: create a minimal valid SQLite database at `path`.
    fn create_sqlite_db(path: &Path) {
        let conn = rusqlite::Connection::open(path).unwrap();
        conn.execute_batch("CREATE TABLE t(x INTEGER);").unwrap();
    }

    // ---------------------------------------------------------------
    // Acceptance: successful patch — tmp renamed to dst, content updated
    // ---------------------------------------------------------------
    // NOTE: Testing the full happy path requires a real encrypted WAL + matching
    // KeyMaterial, which is impractical in a unit test. Instead we test the
    // observable contract via the sub-components and a decrypt-returns-0 scenario.

    #[test]
    fn no_frames_leaves_dst_intact_and_cleans_tmp() {
        // When dispatch_decrypt_wal returns Ok(0), apply_wal_patch should
        // return NoFrames, leave dst unchanged, and remove the tmp file.
        //
        // We simulate this by providing a WAL file that is a valid but empty
        // WAL (just the 32-byte header with zero frames).
        let tmp = TempDir::new().unwrap();
        let dst = tmp.path().join("test.db");
        create_sqlite_db(&dst);
        let original = std::fs::read(&dst).unwrap();

        // Create a minimal WAL header (32 bytes). The magic and version are
        // enough for dispatch_decrypt_wal to parse but find 0 frames.
        let wal = tmp.path().join("test.db-wal");
        let mut wal_header = vec![0u8; 32];
        // WAL magic: 0x377f0682 (little-endian WAL) or 0x377f0683 (big-endian)
        wal_header[..4].copy_from_slice(&0x377f0682u32.to_be_bytes());
        // File format version: 3007000
        wal_header[4..8].copy_from_slice(&3007000u32.to_be_bytes());
        // Page size: 4096
        wal_header[8..12].copy_from_slice(&4096u32.to_be_bytes());
        std::fs::write(&wal, &wal_header).unwrap();

        let km = KeyMaterial::EncKey {
            key: [0u8; 32],
            salt: [0u8; 16],
        };
        let params = wx_decrypt::MACOS_4_1_7_31;

        let result = apply_wal_patch(&wal, &dst, &km, &params);
        assert!(
            matches!(result, WalPatchResult::NoFrames),
            "expected NoFrames, got {result:?}"
        );

        // dst should be unchanged
        assert_eq!(std::fs::read(&dst).unwrap(), original);

        // tmp should be cleaned up
        let tmp_path = dst.with_extension("db.tmp");
        assert!(!tmp_path.exists(), "tmp file should be removed");
    }

    // ---------------------------------------------------------------
    // Acceptance: decrypt failure — dst preserved, tmp cleaned up
    // ---------------------------------------------------------------
    #[test]
    fn decrypt_failure_preserves_dst_and_cleans_tmp() {
        let tmp = TempDir::new().unwrap();
        let dst = tmp.path().join("test.db");
        create_sqlite_db(&dst);
        let original = std::fs::read(&dst).unwrap();

        // Create a WAL with a valid-looking header but garbage frame data.
        // This should cause an HMAC or decrypt error.
        let wal = tmp.path().join("test.db-wal");
        let mut wal_data = vec![0u8; 32 + 24 + 4096]; // header + frame header + one page
        wal_data[..4].copy_from_slice(&0x377f0682u32.to_be_bytes());
        wal_data[4..8].copy_from_slice(&3007000u32.to_be_bytes());
        wal_data[8..12].copy_from_slice(&4096u32.to_be_bytes());
        // Frame header: page number = 1, commit_size = 1
        wal_data[32..36].copy_from_slice(&1u32.to_be_bytes());
        wal_data[36..40].copy_from_slice(&1u32.to_be_bytes());
        // Fill frame body with garbage
        for b in &mut wal_data[56..] {
            *b = 0xAB;
        }
        std::fs::write(&wal, &wal_data).unwrap();

        let km = KeyMaterial::EncKey {
            key: [0u8; 32],
            salt: [0u8; 16],
        };
        let params = wx_decrypt::MACOS_4_1_7_31;

        let result = apply_wal_patch(&wal, &dst, &km, &params);
        assert!(
            matches!(
                result,
                WalPatchResult::ContentFailed(_) | WalPatchResult::IoFailed(_)
            ),
            "expected a failure variant, got {result:?}"
        );

        // dst must be untouched
        assert_eq!(std::fs::read(&dst).unwrap(), original);

        // tmp must be cleaned up
        let tmp_path = dst.with_extension("db.tmp");
        assert!(!tmp_path.exists(), "tmp file should be removed on failure");
    }

    // ---------------------------------------------------------------
    // classify_decrypt_error coverage
    // ---------------------------------------------------------------
    #[test]
    fn classify_content_errors() {
        let cases = vec![
            DecryptError::HmacVerificationFailed { page_num: 1 },
            DecryptError::AesDecryptFailed {
                page_num: 1,
                reason: "test".into(),
            },
            DecryptError::InvalidWalHeader {
                reason: "bad".into(),
            },
            DecryptError::IncorrectKey,
        ];
        for e in cases {
            let r = classify_decrypt_error(e);
            assert!(
                matches!(r, WalPatchResult::ContentFailed(_)),
                "expected ContentFailed, got {r:?}"
            );
        }
    }

    #[test]
    fn classify_io_errors() {
        let cases = vec![
            DecryptError::SaltMismatch,
            DecryptError::NoMatchingEncKey,
            DecryptError::FileTooSmall {
                expected: 100,
                actual: 10,
            },
            DecryptError::AlreadyDecrypted,
        ];
        for e in cases {
            let r = classify_decrypt_error(e);
            assert!(
                matches!(r, WalPatchResult::IoFailed(_)),
                "expected IoFailed, got {r:?}"
            );
        }
    }

    // ---------------------------------------------------------------
    // IO failure: copy fails when dst does not exist
    // ---------------------------------------------------------------
    #[test]
    fn copy_failure_returns_io_failed() {
        let tmp = TempDir::new().unwrap();
        let dst = tmp.path().join("nonexistent.db");
        let wal = tmp.path().join("test.db-wal");
        std::fs::write(&wal, b"dummy").unwrap();

        let km = KeyMaterial::EncKey {
            key: [0u8; 32],
            salt: [0u8; 16],
        };
        let params = wx_decrypt::MACOS_4_1_7_31;

        let result = apply_wal_patch(&wal, &dst, &km, &params);
        assert!(
            matches!(result, WalPatchResult::IoFailed(_)),
            "expected IoFailed when dst missing, got {result:?}"
        );
    }

    // ---------------------------------------------------------------
    // Residual tmp cleanup on entry
    // ---------------------------------------------------------------
    #[test]
    fn residual_tmp_is_cleaned_on_entry() {
        let tmp = TempDir::new().unwrap();
        let dst = tmp.path().join("test.db");
        create_sqlite_db(&dst);

        let tmp_path = dst.with_extension("db.tmp");
        std::fs::write(&tmp_path, b"leftover from crash").unwrap();

        // Create empty WAL (will produce NoFrames)
        let wal = tmp.path().join("test.db-wal");
        let mut wal_header = vec![0u8; 32];
        wal_header[..4].copy_from_slice(&0x377f0682u32.to_be_bytes());
        wal_header[4..8].copy_from_slice(&3007000u32.to_be_bytes());
        wal_header[8..12].copy_from_slice(&4096u32.to_be_bytes());
        std::fs::write(&wal, &wal_header).unwrap();

        let km = KeyMaterial::EncKey {
            key: [0u8; 32],
            salt: [0u8; 16],
        };
        let params = wx_decrypt::MACOS_4_1_7_31;

        let result = apply_wal_patch(&wal, &dst, &km, &params);
        assert!(matches!(result, WalPatchResult::NoFrames));
        assert!(!tmp_path.exists(), "tmp should be cleaned up");
    }
}
