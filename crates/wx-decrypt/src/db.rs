use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;

use aes::cipher::{BlockCipherDecrypt, KeyInit};

use crate::error::DecryptError;
use crate::file_io::open_read_shared;
use crate::kdf::{derive_enc_key, derive_mac_key};
use crate::page::decrypt_page;
use crate::params::CryptoParams;

const SQLITE_HEADER: &[u8; 16] = b"SQLite format 3\0";

/// Decrypt an entire WeChat database file.
///
/// Reads from `input`, writes the decrypted SQLite database to `output`.
/// The `raw_key` is the 32-byte key extracted from WeChat's memory.
pub fn decrypt_db(
    input: &Path,
    output: &Path,
    raw_key: &[u8; 32],
    params: &CryptoParams,
) -> Result<(), DecryptError> {
    let (mut reader, first_page, file_len) = open_and_read_first_page(input, params)?;
    let salt = extract_salt(&first_page, params);

    let enc_key = validate_key(&first_page, raw_key, params).ok_or(DecryptError::IncorrectKey)?;
    let mac_key = derive_mac_key(&enc_key, &salt, params);

    let mut writer = create_output(output)?;
    decrypt_all_pages(
        &mut reader,
        &mut writer,
        &enc_key,
        &mac_key,
        &first_page,
        file_len,
        params,
    )
}

/// Decrypt a database using a pre-derived encryption key and its associated salt.
///
/// Skips the 256K-iteration PBKDF2 key derivation — only the 2-iteration MAC
/// key derivation is performed. Returns `SaltMismatch` if the DB's header salt
/// does not match the provided `salt`.
pub fn decrypt_db_direct(
    input: &Path,
    output: &Path,
    enc_key: &[u8; 32],
    salt: &[u8; 16],
    params: &CryptoParams,
) -> Result<(), DecryptError> {
    let (mut reader, first_page, file_len) = open_and_read_first_page(input, params)?;
    let db_salt = extract_salt(&first_page, params);

    if db_salt != *salt {
        return Err(DecryptError::SaltMismatch);
    }

    let mac_key = derive_mac_key(enc_key, salt, params);

    // Validate HMAC on first page.
    if !verify_first_page_hmac(&first_page, enc_key, &mac_key, params) {
        return Err(DecryptError::IncorrectKey);
    }

    let mut writer = create_output(output)?;
    decrypt_all_pages(
        &mut reader,
        &mut writer,
        enc_key,
        &mac_key,
        &first_page,
        file_len,
        params,
    )
}

/// Validate whether `raw_key` can decrypt the given first page.
///
/// On success (HMAC passes), returns `Some(enc_key)` — the derived encryption key.
/// On failure, returns `None`.
pub fn validate_key(
    first_page: &[u8],
    raw_key: &[u8; 32],
    params: &CryptoParams,
) -> Option<[u8; 32]> {
    if first_page.len() < params.page_size {
        return None;
    }

    let salt = extract_salt(first_page, params);
    let enc_key = derive_enc_key(raw_key, &salt, params);
    let mac_key = derive_mac_key(&enc_key, &salt, params);

    if verify_first_page_hmac(first_page, &enc_key, &mac_key, params) {
        Some(enc_key)
    } else {
        None
    }
}

/// Validate whether a pre-derived `enc_key` matches a DB's first page.
///
/// Extracts the salt from `first_page`, verifies it matches `salt`,
/// derives only the MAC key (2 iterations), and checks the HMAC.
pub fn validate_enc_key(
    first_page: &[u8],
    enc_key: &[u8; 32],
    salt: &[u8; 16],
    params: &CryptoParams,
) -> bool {
    if first_page.len() < params.page_size {
        return false;
    }

    let db_salt = extract_salt(first_page, params);
    if db_salt != *salt {
        return false;
    }

    let mac_key = derive_mac_key(enc_key, &db_salt, params);
    verify_first_page_hmac(first_page, enc_key, &mac_key, params)
}

/// Validate an already-derived AES key using SQLite's fixed first-page header.
///
/// This does not verify the page HMAC and is intended for discovering platform
/// profiles whose reserve/HMAC layout is not known yet.
pub fn validate_enc_key_header(first_page: &[u8], enc_key: &[u8; 32], reserve: usize) -> bool {
    validate_enc_key_header_reserves(first_page, enc_key, &[reserve]).is_some()
}

/// Validate an already-derived AES key against several possible reserve sizes.
///
/// Only the first ciphertext block is decrypted. CBC's first plaintext block is
/// `AES-DEC(ciphertext) XOR IV`, so one AES operation can test every candidate IV.
pub fn validate_enc_key_header_reserves(
    first_page: &[u8],
    enc_key: &[u8; 32],
    reserves: &[usize],
) -> Option<usize> {
    const PAGE_SIZE: usize = 4096;

    if first_page.len() < PAGE_SIZE {
        return None;
    }

    let cipher = aes::Aes256::new(enc_key.into());
    let mut block = aes::Block::default();
    block.copy_from_slice(&first_page[16..32]);
    cipher.decrypt_block(&mut block);

    reserves.iter().copied().find(|&reserve| {
        if !(16..PAGE_SIZE - 16).contains(&reserve) {
            return false;
        }
        let iv = &first_page[PAGE_SIZE - reserve..PAGE_SIZE - reserve + 16];
        block
            .iter()
            .zip(iv)
            .zip(SQLITE_HEADER)
            .all(|((&decrypted, &iv_byte), &header)| decrypted ^ iv_byte == header)
    })
}

/// Read the 16-byte salt from the first page of an encrypted database.
pub fn read_db_salt(db_path: &Path) -> Result<[u8; 16], DecryptError> {
    let mut f = open_read_shared(db_path)?;
    let mut salt = [0u8; 16];
    f.read_exact(&mut salt)?;

    if &salt[..] == b"SQLite format 3\0" {
        return Err(DecryptError::AlreadyDecrypted);
    }

    Ok(salt)
}

/// Read the 16-byte salt from the main DB file for a given path.
///
/// If `path` ends with `-wal`, the corresponding main DB path is derived
/// using `wal_path_to_db_path`. Otherwise, `path` is used directly.
pub fn read_main_db_salt_for_path(path: &Path) -> Result<[u8; 16], DecryptError> {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if name.ends_with("-wal") {
        let db_path = crate::wal::wal_path_to_db_path(path)?;
        read_db_salt(&db_path)
    } else {
        read_db_salt(path)
    }
}

// --- Internal helpers ---

/// Open an encrypted DB, read the first page, and return (reader, first_page, file_len).
fn open_and_read_first_page(
    input: &Path,
    params: &CryptoParams,
) -> Result<(BufReader<File>, Vec<u8>, usize), DecryptError> {
    let file_len = fs::metadata(input)?.len() as usize;
    if file_len < params.page_size {
        return Err(DecryptError::FileTooSmall {
            expected: params.page_size,
            actual: file_len,
        });
    }

    let mut reader = BufReader::new(open_read_shared(input)?);
    let mut first_page = vec![0u8; params.page_size];
    reader.read_exact(&mut first_page)?;

    if first_page[..SQLITE_HEADER.len()] == SQLITE_HEADER[..] {
        return Err(DecryptError::AlreadyDecrypted);
    }

    Ok((reader, first_page, file_len))
}

/// Extract the 16-byte salt from the first page.
fn extract_salt(first_page: &[u8], params: &CryptoParams) -> [u8; 16] {
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&first_page[..params.salt_size]);
    salt
}

/// Create the output file with buffered writer, ensuring parent dirs exist.
fn create_output(output: &Path) -> Result<BufWriter<File>, DecryptError> {
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }
    Ok(BufWriter::new(File::create(output)?))
}

/// Verify the HMAC on the first page using pre-derived keys.
fn verify_first_page_hmac(
    first_page: &[u8],
    _enc_key: &[u8; 32],
    mac_key: &[u8; 32],
    params: &CryptoParams,
) -> bool {
    use hmac::{Hmac, Mac};
    use sha2::Sha512;

    type HmacSha512 = Hmac<Sha512>;

    let offset = params.salt_size; // page 0
    let hmac_data_end = params.page_size - params.reserve + params.iv_size;

    let mut mac = HmacSha512::new_from_slice(mac_key).expect("HMAC key length is always valid");
    mac.update(&first_page[offset..hmac_data_end]);
    mac.update(&1u32.to_le_bytes()); // page 1 (1-indexed)
    let calculated = mac.finalize().into_bytes();

    let stored_hmac = &first_page[hmac_data_end..hmac_data_end + params.hmac_size];
    calculated[..params.hmac_size] == *stored_hmac
}

/// Decrypt all pages (starting from the already-read first page) and write to output.
fn decrypt_all_pages(
    reader: &mut impl Read,
    writer: &mut impl Write,
    enc_key: &[u8; 32],
    mac_key: &[u8; 32],
    first_page: &[u8],
    file_len: usize,
    params: &CryptoParams,
) -> Result<(), DecryptError> {
    // Write SQLite header.
    writer.write_all(SQLITE_HEADER)?;

    // Decrypt page 0 (salt area replaced by SQLite header above).
    let page0_decrypted = decrypt_page(first_page, enc_key, mac_key, 0, params)?;
    writer.write_all(&page0_decrypted)?;

    // Process remaining pages.
    let total_pages = file_len.div_ceil(params.page_size);
    let mut page_buf = vec![0u8; params.page_size];

    for page_num in 1..total_pages as u32 {
        let n = read_full_or_eof(reader, &mut page_buf)?;
        if n == 0 {
            break;
        }
        if n < params.page_size {
            // Partial trailing page — write as-is.
            writer.write_all(&page_buf[..n])?;
            break;
        }

        // Skip all-zero pages (write as-is).
        if page_buf.iter().all(|&b| b == 0) {
            writer.write_all(&page_buf)?;
            continue;
        }

        let decrypted = decrypt_page(&page_buf, enc_key, mac_key, page_num, params)?;
        writer.write_all(&decrypted)?;
    }

    writer.flush()?;
    Ok(())
}

/// Read exactly `buf.len()` bytes, returning the count read (may be less at EOF).
fn read_full_or_eof(reader: &mut impl Read, buf: &mut [u8]) -> Result<usize, std::io::Error> {
    let mut total = 0;
    while total < buf.len() {
        match reader.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
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

        let iv = [0x42u8; 16];
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

        let iv_start = params.page_size - params.reserve;
        page[iv_start..iv_start + params.iv_size].copy_from_slice(&iv);

        let hmac_data_end = params.page_size - params.reserve + params.iv_size;
        let mut mac = HmacSha512::new_from_slice(mac_key).unwrap();
        mac.update(&page[offset..hmac_data_end]);
        mac.update(&(page_num + 1).to_le_bytes());
        let hmac_result = mac.finalize().into_bytes();
        page[hmac_data_end..hmac_data_end + params.hmac_size]
            .copy_from_slice(&hmac_result[..params.hmac_size]);

        page
    }

    fn setup_encrypted_db(dir: &std::path::Path) -> ([u8; 32], [u8; 32], [u8; 32], [u8; 16]) {
        let params = &MACOS_4_1_7_31;
        let raw_key = [0xABu8; 32];
        let salt = [0x01u8; 16];
        let enc_key = derive_enc_key(&raw_key, &salt, params);
        let mac_key = derive_mac_key(&enc_key, &salt, params);

        let page0 =
            build_encrypted_page(b"hello-page0", &enc_key, &mac_key, 0, params, Some(&salt));
        let page1 = build_encrypted_page(b"hello-page1", &enc_key, &mac_key, 1, params, None);
        std::fs::write(dir.join("test.db"), [page0, page1].concat()).unwrap();

        (raw_key, enc_key, mac_key, salt)
    }

    #[test]
    fn test_decrypt_db_direct_produces_identical_output() {
        let params = &MACOS_4_1_7_31;
        let dir = tempfile::tempdir().unwrap();
        let (raw_key, enc_key, _mac_key, salt) = setup_encrypted_db(dir.path());

        let out_raw = dir.path().join("out_raw.db");
        let out_direct = dir.path().join("out_direct.db");
        let input = dir.path().join("test.db");

        decrypt_db(&input, &out_raw, &raw_key, params).unwrap();
        decrypt_db_direct(&input, &out_direct, &enc_key, &salt, params).unwrap();

        assert_eq!(
            std::fs::read(&out_raw).unwrap(),
            std::fs::read(&out_direct).unwrap(),
            "raw and direct decrypt should produce identical output"
        );
    }

    #[test]
    fn test_decrypt_db_direct_wrong_salt_returns_salt_mismatch() {
        let params = &MACOS_4_1_7_31;
        let dir = tempfile::tempdir().unwrap();
        let (_raw_key, enc_key, _mac_key, _salt) = setup_encrypted_db(dir.path());

        let wrong_salt = [0x99u8; 16];
        let input = dir.path().join("test.db");
        let output = dir.path().join("out.db");

        let err = decrypt_db_direct(&input, &output, &enc_key, &wrong_salt, params).unwrap_err();
        assert!(matches!(err, DecryptError::SaltMismatch));
    }

    #[test]
    fn test_validate_enc_key_correct() {
        let params = &MACOS_4_1_7_31;
        let raw_key = [0xABu8; 32];
        let salt = [0x01u8; 16];
        let enc_key = derive_enc_key(&raw_key, &salt, params);
        let mac_key = derive_mac_key(&enc_key, &salt, params);

        let first_page = build_encrypted_page(b"test", &enc_key, &mac_key, 0, params, Some(&salt));
        assert!(validate_enc_key(&first_page, &enc_key, &salt, params));
    }

    #[test]
    fn test_validate_enc_key_wrong_salt() {
        let params = &MACOS_4_1_7_31;
        let raw_key = [0xABu8; 32];
        let salt = [0x01u8; 16];
        let enc_key = derive_enc_key(&raw_key, &salt, params);
        let mac_key = derive_mac_key(&enc_key, &salt, params);

        let first_page = build_encrypted_page(b"test", &enc_key, &mac_key, 0, params, Some(&salt));
        let wrong_salt = [0x99u8; 16];
        assert!(!validate_enc_key(
            &first_page,
            &enc_key,
            &wrong_salt,
            params
        ));
    }

    #[test]
    fn test_validate_enc_key_wrong_key() {
        let params = &MACOS_4_1_7_31;
        let raw_key = [0xABu8; 32];
        let salt = [0x01u8; 16];
        let enc_key = derive_enc_key(&raw_key, &salt, params);
        let mac_key = derive_mac_key(&enc_key, &salt, params);

        let first_page = build_encrypted_page(b"test", &enc_key, &mac_key, 0, params, Some(&salt));
        let wrong_key = [0xCDu8; 32];
        assert!(!validate_enc_key(&first_page, &wrong_key, &salt, params));
    }

    #[test]
    fn test_validate_enc_key_header_reserves() {
        use aes::cipher::{block_padding::NoPadding, BlockModeEncrypt, KeyIvInit};

        type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

        let key = [0xAB; 32];
        let iv = [0x42; 16];
        let reserve = 48;
        let mut ciphertext = SQLITE_HEADER.to_vec();
        Aes256CbcEnc::new((&key).into(), (&iv).into())
            .encrypt_padded::<NoPadding>(&mut ciphertext, SQLITE_HEADER.len())
            .unwrap();

        let mut first_page = vec![0u8; 4096];
        first_page[16..32].copy_from_slice(&ciphertext);
        first_page[4096 - reserve..4096 - reserve + 16].copy_from_slice(&iv);

        assert_eq!(
            validate_enc_key_header_reserves(&first_page, &key, &[80, 48, 64]),
            Some(48)
        );
        assert_eq!(
            validate_enc_key_header_reserves(&first_page, &[0xCD; 32], &[80, 48, 64]),
            None
        );
    }

    #[test]
    fn test_read_db_salt() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let mut data = vec![0u8; 4096];
        data[..16].copy_from_slice(&[0x01u8; 16]);
        std::fs::write(&db_path, &data).unwrap();

        let salt = read_db_salt(&db_path).unwrap();
        assert_eq!(salt, [0x01u8; 16]);
    }

    #[test]
    fn test_read_db_salt_already_decrypted() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let mut data = vec![0u8; 4096];
        data[..16].copy_from_slice(b"SQLite format 3\0");
        std::fs::write(&db_path, &data).unwrap();

        let err = read_db_salt(&db_path).unwrap_err();
        assert!(matches!(err, DecryptError::AlreadyDecrypted));
    }

    #[test]
    fn test_read_main_db_salt_for_db_path() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("session.db");
        let mut data = vec![0u8; 4096];
        data[..16].copy_from_slice(&[0x42u8; 16]);
        std::fs::write(&db_path, &data).unwrap();

        let salt = read_main_db_salt_for_path(&db_path).unwrap();
        assert_eq!(salt, [0x42u8; 16]);
    }

    #[test]
    fn test_read_main_db_salt_for_wal_path() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("session.db");
        let mut data = vec![0u8; 4096];
        data[..16].copy_from_slice(&[0x55u8; 16]);
        std::fs::write(&db_path, data).unwrap();

        let wal_path = dir.path().join("session.db-wal");
        std::fs::write(&wal_path, [0u8; 32]).unwrap(); // WAL file exists

        let salt = read_main_db_salt_for_path(&wal_path).unwrap();
        assert_eq!(salt, [0x55u8; 16]);
    }

    #[test]
    fn test_read_main_db_salt_for_missing_db_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let wal_path = dir.path().join("missing.db-wal");
        std::fs::write(&wal_path, [0u8; 32]).unwrap();

        let err = read_main_db_salt_for_path(&wal_path).unwrap_err();
        assert!(matches!(err, DecryptError::Io(_)));
    }
}
