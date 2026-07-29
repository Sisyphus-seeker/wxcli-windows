//! WAL (Write-Ahead Log) decryption for encrypted SQLite databases.
//!
//! SQLite WAL files consist of a 32-byte header followed by N frames.
//! Each frame has a 24-byte frame header and a full page of data.
//! In encrypted WeChat databases, the page data within each frame is
//! encrypted using the same parameters as the main database.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use crate::db::read_db_salt;
use crate::error::DecryptError;
use crate::file_io::open_read_shared;
use crate::kdf::{derive_enc_key, derive_mac_key};
use crate::page::decrypt_page;
use crate::params::CryptoParams;

/// WAL file header size in bytes.
const WAL_HEADER_SIZE: usize = 32;

/// WAL frame header size in bytes.
const WAL_FRAME_HEADER_SIZE: usize = 24;

/// SQLite WAL magic numbers (big-endian and little-endian checksum variants).
const WAL_MAGIC_BE: u32 = 0x377f_0682;
const WAL_MAGIC_LE: u32 = 0x377f_0683;

/// Maximum valid page number (sanity check).
const MAX_PAGE_NUMBER: u32 = 1_000_000;

/// Parsed WAL file header.
#[derive(Debug, Clone)]
struct WalHeader {
    salt1: u32,
    salt2: u32,
}

/// Parsed WAL frame header.
#[derive(Debug, Clone)]
struct WalFrameHeader {
    page_number: u32,
    commit_size: u32,
    salt1: u32,
    salt2: u32,
}

impl WalHeader {
    fn parse(buf: &[u8; WAL_HEADER_SIZE]) -> Result<Self, DecryptError> {
        let magic = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        if magic != WAL_MAGIC_BE && magic != WAL_MAGIC_LE {
            return Err(DecryptError::InvalidWalHeader {
                reason: format!("bad magic: 0x{magic:08x}"),
            });
        }

        let salt1 = u32::from_be_bytes([buf[16], buf[17], buf[18], buf[19]]);
        let salt2 = u32::from_be_bytes([buf[20], buf[21], buf[22], buf[23]]);

        Ok(WalHeader { salt1, salt2 })
    }
}

impl WalFrameHeader {
    fn parse(buf: &[u8; WAL_FRAME_HEADER_SIZE]) -> Self {
        WalFrameHeader {
            page_number: u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]),
            commit_size: u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
            salt1: u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]),
            salt2: u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]),
        }
    }

    fn is_valid(&self, wal_header: &WalHeader) -> bool {
        self.page_number > 0
            && self.page_number <= MAX_PAGE_NUMBER
            && self.salt1 == wal_header.salt1
            && self.salt2 == wal_header.salt2
    }
}

/// Decrypt valid WAL frames and patch them into a decrypted database file.
///
/// Reads the encrypted WAL file at `wal_path`, decrypts each valid frame's page
/// data, and writes it to the corresponding offset in `decrypted_db_path`.
///
/// Returns the number of frames successfully patched.
pub fn decrypt_wal(
    wal_path: &Path,
    decrypted_db_path: &Path,
    raw_key: &[u8; 32],
    params: &CryptoParams,
) -> Result<usize, DecryptError> {
    let (mut wal_file, wal_header, wal_len) = open_wal(wal_path)?;
    if wal_len < WAL_HEADER_SIZE {
        return Ok(0);
    }

    let encrypted_db_path = wal_path_to_db_path(wal_path)?;
    let salt = read_db_salt(&encrypted_db_path)?;

    let enc_key = derive_enc_key(raw_key, &salt, params);
    let mac_key = derive_mac_key(&enc_key, &salt, params);

    let mut db_file = std::fs::OpenOptions::new()
        .write(true)
        .read(true)
        .open(decrypted_db_path)?;

    decrypt_wal_frames(
        &mut wal_file,
        &mut db_file,
        &enc_key,
        &mac_key,
        &wal_header,
        wal_len,
        params,
    )
}

/// Decrypt WAL frames using a pre-derived encryption key and salt.
///
/// Skips the 256K-iteration PBKDF2 key derivation.
pub fn decrypt_wal_direct(
    wal_path: &Path,
    decrypted_db_path: &Path,
    enc_key: &[u8; 32],
    salt: &[u8; 16],
    params: &CryptoParams,
) -> Result<usize, DecryptError> {
    let (mut wal_file, wal_header, wal_len) = open_wal(wal_path)?;
    if wal_len < WAL_HEADER_SIZE {
        return Ok(0);
    }

    let mac_key = derive_mac_key(enc_key, salt, params);

    let mut db_file = std::fs::OpenOptions::new()
        .write(true)
        .read(true)
        .open(decrypted_db_path)?;

    decrypt_wal_frames(
        &mut wal_file,
        &mut db_file,
        enc_key,
        &mac_key,
        &wal_header,
        wal_len,
        params,
    )
}

// --- Internal helpers ---

/// Open the WAL file, parse its header, and return (file, header, len).
/// Returns Ok with wal_len=0 for empty/too-small WAL files.
fn open_wal(wal_path: &Path) -> Result<(File, WalHeader, usize), DecryptError> {
    let wal_len = std::fs::metadata(wal_path)?.len() as usize;
    if wal_len < WAL_HEADER_SIZE {
        // Return a dummy header — caller checks wal_len and returns Ok(0).
        return Ok((
            open_read_shared(wal_path)?,
            WalHeader { salt1: 0, salt2: 0 },
            wal_len,
        ));
    }

    let mut wal_file = open_read_shared(wal_path)?;
    let mut wal_hdr_buf = [0u8; WAL_HEADER_SIZE];
    wal_file.read_exact(&mut wal_hdr_buf)?;
    let wal_header = WalHeader::parse(&wal_hdr_buf)?;

    Ok((wal_file, wal_header, wal_len))
}

/// Process WAL frames: decrypt each valid frame up to the last commit boundary
/// and patch it into the DB file.
///
/// Uses a two-phase approach to match SQLite WAL reader semantics:
/// - Phase 1: Scan all frame headers to find the last frame with `commit_size > 0`.
/// - Phase 2: Apply frames 0..=last_commit_idx, skipping the rest.
///
/// Returns `Ok(0)` if there are no committed transactions in the WAL.
fn decrypt_wal_frames(
    wal_file: &mut File,
    db_file: &mut File,
    enc_key: &[u8; 32],
    mac_key: &[u8; 32],
    wal_header: &WalHeader,
    wal_len: usize,
    params: &CryptoParams,
) -> Result<usize, DecryptError> {
    let frame_size = WAL_FRAME_HEADER_SIZE + params.page_size;
    let mut frame_hdr_buf = [0u8; WAL_FRAME_HEADER_SIZE];

    // Phase 1: Find the last committed frame (commit_size > 0).
    let total_frames = wal_len.saturating_sub(WAL_HEADER_SIZE) / frame_size;
    let mut last_commit_idx: Option<usize> = None;
    for i in 0..total_frames {
        let hdr_offset = (WAL_HEADER_SIZE + i * frame_size) as u64;
        wal_file.seek(SeekFrom::Start(hdr_offset))?;
        wal_file.read_exact(&mut frame_hdr_buf)?;
        let fh = WalFrameHeader::parse(&frame_hdr_buf);
        if fh.is_valid(wal_header) && fh.commit_size > 0 {
            last_commit_idx = Some(i);
        }
    }

    let Some(last_commit) = last_commit_idx else {
        // No committed transaction found; nothing to apply.
        return Ok(0);
    };

    // Phase 2: Apply frames 0..=last_commit sequentially.
    let mut page_buf = vec![0u8; params.page_size];
    let mut patched: usize = 0;

    wal_file.seek(SeekFrom::Start(WAL_HEADER_SIZE as u64))?;
    for _ in 0..=last_commit {
        wal_file.read_exact(&mut frame_hdr_buf)?;
        let frame_hdr = WalFrameHeader::parse(&frame_hdr_buf);
        wal_file.read_exact(&mut page_buf)?;

        if !frame_hdr.is_valid(wal_header) {
            continue;
        }

        if page_buf.iter().all(|&b| b == 0) {
            continue;
        }

        // WAL page_number is 1-indexed; decrypt_page expects 0-indexed.
        let page_num_0 = frame_hdr.page_number - 1;

        let decrypted = decrypt_page(&page_buf, enc_key, mac_key, page_num_0, params)?;

        // For page 0, decrypt_page returns 4080 bytes (skips salt area).
        // Prepend the SQLite header to restore full page size.
        let write_data = if page_num_0 == 0 {
            let mut full = Vec::with_capacity(params.page_size);
            full.extend_from_slice(b"SQLite format 3\0");
            full.extend_from_slice(&decrypted);
            full
        } else {
            decrypted
        };

        let offset = (page_num_0 as u64) * (params.page_size as u64);
        db_file.seek(SeekFrom::Start(offset))?;
        db_file.write_all(&write_data)?;
        patched += 1;
    }

    db_file.flush()?;
    Ok(patched)
}

/// Derive the encrypted DB path from a WAL path by stripping the "-wal" suffix.
pub(crate) fn wal_path_to_db_path(wal_path: &Path) -> Result<std::path::PathBuf, DecryptError> {
    let wal_name = wal_path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| DecryptError::InvalidWalHeader {
            reason: "cannot determine WAL filename".to_string(),
        })?;

    if !wal_name.ends_with("-wal") {
        return Err(DecryptError::InvalidWalHeader {
            reason: format!("WAL path does not end with -wal: {wal_name}"),
        });
    }

    let db_name = &wal_name[..wal_name.len() - 4];
    Ok(wal_path.with_file_name(db_name))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_wal_header(salt1: u32, salt2: u32) -> [u8; WAL_HEADER_SIZE] {
        let mut buf = [0u8; WAL_HEADER_SIZE];
        buf[0..4].copy_from_slice(&WAL_MAGIC_BE.to_be_bytes());
        buf[4..8].copy_from_slice(&3007000u32.to_be_bytes());
        buf[8..12].copy_from_slice(&4096u32.to_be_bytes());
        buf[12..16].copy_from_slice(&1u32.to_be_bytes());
        buf[16..20].copy_from_slice(&salt1.to_be_bytes());
        buf[20..24].copy_from_slice(&salt2.to_be_bytes());
        buf
    }

    fn make_frame_header(
        pgno: u32,
        commit_size: u32,
        salt1: u32,
        salt2: u32,
    ) -> [u8; WAL_FRAME_HEADER_SIZE] {
        let mut buf = [0u8; WAL_FRAME_HEADER_SIZE];
        buf[0..4].copy_from_slice(&pgno.to_be_bytes());
        buf[4..8].copy_from_slice(&commit_size.to_be_bytes());
        buf[8..12].copy_from_slice(&salt1.to_be_bytes());
        buf[12..16].copy_from_slice(&salt2.to_be_bytes());
        buf
    }

    #[test]
    fn test_wal_header_parse_valid() {
        let buf = make_wal_header(0xAABBCCDD, 0x11223344);
        let hdr = WalHeader::parse(&buf).unwrap();
        assert_eq!(hdr.salt1, 0xAABBCCDD);
        assert_eq!(hdr.salt2, 0x11223344);
    }

    #[test]
    fn test_wal_header_parse_le_magic() {
        let mut buf = make_wal_header(1, 2);
        buf[0..4].copy_from_slice(&WAL_MAGIC_LE.to_be_bytes());
        let hdr = WalHeader::parse(&buf).unwrap();
        assert_eq!(hdr.salt1, 1);
    }

    #[test]
    fn test_wal_header_parse_bad_magic() {
        let mut buf = [0u8; WAL_HEADER_SIZE];
        buf[0..4].copy_from_slice(&0xDEADBEEFu32.to_be_bytes());
        let err = WalHeader::parse(&buf).unwrap_err();
        assert!(err.to_string().contains("bad magic"));
    }

    #[test]
    fn test_frame_header_valid() {
        let wal_hdr = WalHeader {
            salt1: 100,
            salt2: 200,
        };
        let fh = WalFrameHeader::parse(&make_frame_header(5, 0, 100, 200));
        assert!(fh.is_valid(&wal_hdr));
        assert_eq!(fh.page_number, 5);
    }

    #[test]
    fn test_frame_header_stale_salt() {
        let wal_hdr = WalHeader {
            salt1: 100,
            salt2: 200,
        };
        let fh = WalFrameHeader::parse(&make_frame_header(5, 0, 99, 200));
        assert!(!fh.is_valid(&wal_hdr));
    }

    #[test]
    fn test_frame_header_zero_pgno() {
        let wal_hdr = WalHeader {
            salt1: 100,
            salt2: 200,
        };
        let fh = WalFrameHeader::parse(&make_frame_header(0, 0, 100, 200));
        assert!(!fh.is_valid(&wal_hdr));
    }

    #[test]
    fn test_frame_header_pgno_too_large() {
        let wal_hdr = WalHeader {
            salt1: 100,
            salt2: 200,
        };
        let fh = WalFrameHeader::parse(&make_frame_header(MAX_PAGE_NUMBER + 1, 0, 100, 200));
        assert!(!fh.is_valid(&wal_hdr));
    }

    use crate::kdf::{derive_enc_key, derive_mac_key};
    use crate::params::MACOS_4_1_7_31;

    /// Build a fake encrypted page (reverse of decrypt_page).
    fn build_encrypted_page(
        content: &[u8],
        enc_key: &[u8; 32],
        mac_key: &[u8; 32],
        page_num: u32,
        params: &CryptoParams,
        salt: Option<&[u8; 16]>,
    ) -> Vec<u8> {
        use aes::cipher::{block_padding::NoPadding, BlockModeEncrypt, KeyIvInit};
        use hmac::{Hmac, Mac};
        use sha2::Sha512;

        type HmacSha512 = Hmac<Sha512>;
        type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

        let iv = [0x42u8; 16]; // deterministic IV for testing
        let offset = if page_num == 0 { params.salt_size } else { 0 };

        let data_len = params.page_size - params.reserve - offset;
        let mut plaintext = vec![0u8; data_len];
        let copy_len = content.len().min(data_len);
        plaintext[..copy_len].copy_from_slice(&content[..copy_len]);

        let mut ciphertext = plaintext.clone();
        Aes256CbcEnc::new(enc_key.into(), (&iv).into())
            .encrypt_padded::<NoPadding>(&mut ciphertext, data_len)
            .expect("encryption should not fail");

        let mut page = vec![0u8; params.page_size];
        if page_num == 0 {
            page[..params.salt_size].copy_from_slice(salt.unwrap());
            page[offset..offset + data_len].copy_from_slice(&ciphertext);
        } else {
            page[..data_len].copy_from_slice(&ciphertext);
        }

        // Place IV in reserve area
        let iv_start = params.page_size - params.reserve;
        page[iv_start..iv_start + params.iv_size].copy_from_slice(&iv);

        // Compute HMAC
        let hmac_data_end = params.page_size - params.reserve + params.iv_size;
        let mut mac = HmacSha512::new_from_slice(mac_key).unwrap();
        mac.update(&page[offset..hmac_data_end]);
        mac.update(&(page_num + 1).to_le_bytes());
        let hmac_result = mac.finalize().into_bytes();
        page[hmac_data_end..hmac_data_end + params.hmac_size]
            .copy_from_slice(&hmac_result[..params.hmac_size]);

        page
    }

    /// Build a WAL file in memory: header + frames.
    fn build_wal_file(salt1: u32, salt2: u32, frames: &[(u32, u32, u32, u32, &[u8])]) -> Vec<u8> {
        let mut wal = make_wal_header(salt1, salt2).to_vec();
        for &(pgno, commit_size, fsalt1, fsalt2, page_data) in frames {
            let fh = make_frame_header(pgno, commit_size, fsalt1, fsalt2);
            wal.extend_from_slice(&fh);
            wal.extend_from_slice(page_data);
        }
        wal
    }

    #[test]
    fn test_decrypt_wal_patches_valid_frames() {
        let params = &MACOS_4_1_7_31;
        let raw_key = [0xABu8; 32];
        let salt = [0x01u8; 16];
        let enc_key = derive_enc_key(&raw_key, &salt, params);
        let mac_key = derive_mac_key(&enc_key, &salt, params);

        let dir = tempfile::tempdir().unwrap();

        // Create fake encrypted DB (2 pages)
        let enc_db_path = dir.path().join("test.db");
        let page0 = build_encrypted_page(
            b"page0-original",
            &enc_key,
            &mac_key,
            0,
            params,
            Some(&salt),
        );
        let page1 = build_encrypted_page(b"page1-original", &enc_key, &mac_key, 1, params, None);
        std::fs::write(&enc_db_path, [page0, page1].concat()).unwrap();

        // Create decrypted DB placeholder (2 pages of zeros)
        let dec_db_path = dir.path().join("test_decrypted.db");
        std::fs::write(&dec_db_path, vec![0u8; params.page_size * 2]).unwrap();

        // WAL with 1 valid frame (page 2, 1-indexed) + 1 stale frame
        let new_page1 =
            build_encrypted_page(b"page1-from-wal", &enc_key, &mac_key, 1, params, None);
        let stale_page = build_encrypted_page(b"stale-data", &enc_key, &mac_key, 1, params, None);
        let wal_salt1: u32 = 0xAAAA;
        let wal_salt2: u32 = 0xBBBB;
        let wal_data = build_wal_file(
            wal_salt1,
            wal_salt2,
            &[
                (2, 1, wal_salt1, wal_salt2, &new_page1),
                (2, 0, 0xDEAD, 0xBEEF, &stale_page),
            ],
        );
        let wal_path = dir.path().join("test.db-wal");
        std::fs::write(&wal_path, &wal_data).unwrap();

        let patched = decrypt_wal(&wal_path, &dec_db_path, &raw_key, params).unwrap();
        assert_eq!(patched, 1, "should patch exactly 1 valid frame");

        // Verify patched page contains the expected decrypted content.
        let result = std::fs::read(&dec_db_path).unwrap();
        let patched_page = &result[params.page_size..params.page_size * 2];
        assert_eq!(
            &patched_page[..14],
            b"page1-from-wal",
            "patched page content should match WAL frame plaintext"
        );
        assert!(
            patched_page[14..params.page_size - params.reserve]
                .iter()
                .all(|&b| b == 0),
            "rest of data area should be zero-padded"
        );
    }

    #[test]
    fn test_decrypt_wal_patches_page0_with_sqlite_header() {
        let params = &MACOS_4_1_7_31;
        let raw_key = [0xABu8; 32];
        let salt = [0x01u8; 16];
        let enc_key = derive_enc_key(&raw_key, &salt, params);
        let mac_key = derive_mac_key(&enc_key, &salt, params);

        let dir = tempfile::tempdir().unwrap();

        // Create fake encrypted DB (1 page)
        let enc_db_path = dir.path().join("test.db");
        let page0 = build_encrypted_page(
            b"page0-original",
            &enc_key,
            &mac_key,
            0,
            params,
            Some(&salt),
        );
        std::fs::write(&enc_db_path, &page0).unwrap();

        // Create decrypted DB placeholder (1 page of zeros)
        let dec_db_path = dir.path().join("test_decrypted.db");
        std::fs::write(&dec_db_path, vec![0u8; params.page_size]).unwrap();

        // WAL with 1 valid frame for page 1 (1-indexed = page 0, 0-indexed)
        let new_page0 = build_encrypted_page(
            b"page0-from-wal",
            &enc_key,
            &mac_key,
            0,
            params,
            Some(&salt),
        );
        let wal_salt1: u32 = 0x1111;
        let wal_salt2: u32 = 0x2222;
        let wal_data = build_wal_file(
            wal_salt1,
            wal_salt2,
            &[(1, 1, wal_salt1, wal_salt2, &new_page0)],
        );
        let wal_path = dir.path().join("test.db-wal");
        std::fs::write(&wal_path, &wal_data).unwrap();

        let patched = decrypt_wal(&wal_path, &dec_db_path, &raw_key, params).unwrap();
        assert_eq!(patched, 1);

        let result = std::fs::read(&dec_db_path).unwrap();
        assert_eq!(
            &result[..16],
            b"SQLite format 3\0",
            "page 0 should have SQLite header prepended"
        );
        assert_eq!(
            &result[16..16 + 14],
            b"page0-from-wal",
            "page 0 decrypted content should match WAL frame plaintext"
        );
    }

    #[test]
    fn test_decrypt_wal_header_only_returns_zero() {
        let params = &MACOS_4_1_7_31;
        let dir = tempfile::tempdir().unwrap();

        let enc_db_path = dir.path().join("test.db");
        std::fs::write(&enc_db_path, vec![0xAAu8; params.page_size]).unwrap();
        let dec_db_path = dir.path().join("test_dec.db");
        std::fs::write(&dec_db_path, vec![0u8; params.page_size]).unwrap();

        let wal_data = make_wal_header(1, 2).to_vec();
        let wal_path = dir.path().join("test.db-wal");
        std::fs::write(&wal_path, &wal_data).unwrap();

        let result = decrypt_wal(&wal_path, &dec_db_path, &[0u8; 32], params).unwrap();
        assert_eq!(result, 0, "header-only WAL should return Ok(0)");
    }

    #[test]
    fn test_decrypt_wal_too_small_returns_zero() {
        let params = &MACOS_4_1_7_31;
        let dir = tempfile::tempdir().unwrap();

        let wal_path = dir.path().join("tiny.db-wal");
        std::fs::write(&wal_path, [0u8; 16]).unwrap();

        let result = decrypt_wal(&wal_path, Path::new("/nonexistent"), &[0u8; 32], params);
        assert_eq!(
            result.unwrap(),
            0,
            "WAL smaller than header should return Ok(0)"
        );
    }

    #[test]
    fn test_decrypt_wal_zero_bytes_returns_zero() {
        let params = &MACOS_4_1_7_31;
        let dir = tempfile::tempdir().unwrap();

        let wal_path = dir.path().join("empty.db-wal");
        std::fs::write(&wal_path, []).unwrap();

        let result = decrypt_wal(&wal_path, Path::new("/nonexistent"), &[0u8; 32], params);
        assert_eq!(result.unwrap(), 0, "0-byte WAL should return Ok(0)");
    }

    #[test]
    fn test_wal_path_to_db_path() {
        let wal = Path::new("/data/session/session.db-wal");
        let db = wal_path_to_db_path(wal).unwrap();
        assert_eq!(db, Path::new("/data/session/session.db"));
    }

    #[test]
    fn test_wal_path_to_db_path_invalid() {
        let bad = Path::new("/data/session/session.db");
        assert!(wal_path_to_db_path(bad).is_err());
    }

    // --- Commit boundary tests ---

    /// Helper: build a minimal WAL + decrypted DB pair for commit boundary tests.
    ///
    /// Returns `(wal_path, dec_db_path, tempdir)`.
    fn setup_commit_boundary_test(
        frames: &[(u32, u32, &[u8])], // (pgno, commit_size, page_content)
    ) -> (std::path::PathBuf, std::path::PathBuf, tempfile::TempDir) {
        let params = &MACOS_4_1_7_31;
        let raw_key = [0xCDu8; 32];
        let salt = [0x02u8; 16];
        let enc_key = derive_enc_key(&raw_key, &salt, params);
        let mac_key = derive_mac_key(&enc_key, &salt, params);
        let wal_salt1: u32 = 0x1234;
        let wal_salt2: u32 = 0x5678;

        let dir = tempfile::tempdir().unwrap();

        // Build encrypted pages for all unique page numbers.
        let max_pgno = frames.iter().map(|f| f.0).max().unwrap_or(1);

        // Create a fake encrypted DB large enough for all pages.
        let enc_db_path = dir.path().join("cbt.db");
        let mut enc_db = vec![0xFFu8; params.page_size * max_pgno as usize];
        // Page 0 (1-indexed page 1) needs a salt prefix.
        enc_db[..16].copy_from_slice(&salt);
        std::fs::write(&enc_db_path, &enc_db).unwrap();

        // Create blank decrypted DB.
        let dec_db_path = dir.path().join("cbt_dec.db");
        std::fs::write(
            &dec_db_path,
            vec![0u8; params.page_size * max_pgno as usize],
        )
        .unwrap();

        // Build WAL frames.
        let frame_data: Vec<(u32, u32, u32, u32, Vec<u8>)> = frames
            .iter()
            .map(|&(pgno, commit_size, content)| {
                let page_num_0 = pgno - 1;
                let page = build_encrypted_page(
                    content,
                    &enc_key,
                    &mac_key,
                    page_num_0,
                    params,
                    if page_num_0 == 0 { Some(&salt) } else { None },
                );
                (pgno, commit_size, wal_salt1, wal_salt2, page)
            })
            .collect();

        let frame_refs: Vec<(u32, u32, u32, u32, &[u8])> = frame_data
            .iter()
            .map(|(pg, cs, s1, s2, data)| (*pg, *cs, *s1, *s2, data.as_slice()))
            .collect();

        let wal_bytes = build_wal_file(wal_salt1, wal_salt2, &frame_refs);
        let wal_path = dir.path().join("cbt.db-wal");
        std::fs::write(&wal_path, &wal_bytes).unwrap();

        (wal_path, dec_db_path, dir)
    }

    /// Content-unique page data for testing (avoids all-zero page skip).
    fn page_content(tag: u8) -> Vec<u8> {
        vec![tag; 32]
    }

    #[test]
    fn test_commit_boundary_partial_transaction_skipped() {
        // Frame A: pgno=1, commit_size=0 (non-commit frame of a transaction)
        // Frame B: pgno=2, commit_size=5 (commit frame — this is the boundary)
        // Frame C: pgno=3, commit_size=0 (new uncommitted transaction — must be skipped)
        let pa = page_content(0xA1);
        let pb = page_content(0xA2);
        let pc = page_content(0xA3);
        let frames: &[(u32, u32, &[u8])] = &[(1, 0, &pa), (2, 5, &pb), (3, 0, &pc)];
        let (wal_path, dec_db_path, _dir) = setup_commit_boundary_test(frames);

        let params = &MACOS_4_1_7_31;
        let raw_key = [0xCDu8; 32];
        let patched = decrypt_wal(&wal_path, &dec_db_path, &raw_key, params).unwrap();

        // Frames A and B applied; frame C skipped.
        assert_eq!(patched, 2, "frames A and B should be patched; C skipped");
    }

    #[test]
    fn test_no_commit_frame_returns_zero() {
        // All frames have commit_size=0 — no committed transaction.
        let pa = page_content(0xB1);
        let pb = page_content(0xB2);
        let frames: &[(u32, u32, &[u8])] = &[(1, 0, &pa), (2, 0, &pb)];
        let (wal_path, dec_db_path, _dir) = setup_commit_boundary_test(frames);

        let params = &MACOS_4_1_7_31;
        let raw_key = [0xCDu8; 32];
        let patched = decrypt_wal(&wal_path, &dec_db_path, &raw_key, params).unwrap();

        assert_eq!(
            patched, 0,
            "no commit frame means nothing should be applied"
        );
    }

    #[test]
    fn test_all_committed_frames_applied() {
        // Both frames are commit frames — all should be applied.
        let pa = page_content(0xC1);
        let pb = page_content(0xC2);
        let frames: &[(u32, u32, &[u8])] = &[(1, 3, &pa), (2, 7, &pb)];
        let (wal_path, dec_db_path, _dir) = setup_commit_boundary_test(frames);

        let params = &MACOS_4_1_7_31;
        let raw_key = [0xCDu8; 32];
        let patched = decrypt_wal(&wal_path, &dec_db_path, &raw_key, params).unwrap();

        assert_eq!(patched, 2, "both committed frames should be applied");
    }

    #[test]
    fn test_commit_boundary_multi_transaction_last_wins() {
        // 5 frames, two complete transactions + one incomplete:
        // Frame 0 (pgno=2, commit_size=0): non-commit, part of tx1
        // Frame 1 (pgno=3, commit_size=3): commit, ends tx1
        // Frame 2 (pgno=4, commit_size=0): non-commit, part of tx2
        // Frame 3 (pgno=5, commit_size=6): commit, ends tx2
        // Frame 4 (pgno=6, commit_size=0): incomplete tx3, must be SKIPPED
        let p0 = page_content(0xD0);
        let p1 = page_content(0xD1);
        let p2 = page_content(0xD2);
        let p3 = page_content(0xD3);
        let p4 = page_content(0xD4);
        let frames: &[(u32, u32, &[u8])] = &[
            (2, 0, &p0),
            (3, 3, &p1),
            (4, 0, &p2),
            (5, 6, &p3),
            (6, 0, &p4),
        ];
        let (wal_path, dec_db_path, _dir) = setup_commit_boundary_test(frames);

        let params = &MACOS_4_1_7_31;
        let raw_key = [0xCDu8; 32];
        let patched = decrypt_wal(&wal_path, &dec_db_path, &raw_key, params).unwrap();

        // Frames 0-3 applied (4 frames); frame 4 skipped.
        assert_eq!(patched, 4, "frames 0-3 should be patched; frame 4 skipped");

        // Verify frame 4 (pgno=6, 0-indexed=5) was NOT written to the DB.
        let db_contents = std::fs::read(&dec_db_path).unwrap();
        let page5_offset = 5 * params.page_size;
        let page5 = &db_contents[page5_offset..page5_offset + params.page_size];
        assert!(
            page5.iter().all(|&b| b == 0),
            "page 5 (frame 4, pgno=6) should remain zero — not patched"
        );
    }

    #[test]
    fn test_decrypt_wal_direct_produces_same_result() {
        let params = &MACOS_4_1_7_31;
        let raw_key = [0xABu8; 32];
        let salt = [0x01u8; 16];
        let enc_key = derive_enc_key(&raw_key, &salt, params);
        let mac_key = derive_mac_key(&enc_key, &salt, params);

        let dir = tempfile::tempdir().unwrap();

        // Create fake encrypted DB (2 pages)
        let enc_db_path = dir.path().join("test.db");
        let page0 = build_encrypted_page(
            b"wal-direct-test",
            &enc_key,
            &mac_key,
            0,
            params,
            Some(&salt),
        );
        let page1 = build_encrypted_page(b"page1-data", &enc_key, &mac_key, 1, params, None);
        std::fs::write(&enc_db_path, [page0, page1].concat()).unwrap();

        let wal_salt1: u32 = 0x5555;
        let wal_salt2: u32 = 0x6666;
        let new_page1 = build_encrypted_page(b"page1-updated", &enc_key, &mac_key, 1, params, None);
        let wal_data = build_wal_file(
            wal_salt1,
            wal_salt2,
            &[(2, 1, wal_salt1, wal_salt2, &new_page1)],
        );
        let wal_path = dir.path().join("test.db-wal");
        std::fs::write(&wal_path, &wal_data).unwrap();

        // Decrypt with raw key
        let dec_raw = dir.path().join("dec_raw.db");
        std::fs::write(&dec_raw, vec![0u8; params.page_size * 2]).unwrap();
        let patched_raw = decrypt_wal(&wal_path, &dec_raw, &raw_key, params).unwrap();

        // Decrypt with direct enc_key
        let dec_direct = dir.path().join("dec_direct.db");
        std::fs::write(&dec_direct, vec![0u8; params.page_size * 2]).unwrap();
        let patched_direct =
            decrypt_wal_direct(&wal_path, &dec_direct, &enc_key, &salt, params).unwrap();

        assert_eq!(patched_raw, patched_direct);
        assert_eq!(
            std::fs::read(&dec_raw).unwrap(),
            std::fs::read(&dec_direct).unwrap(),
        );
    }
}
