//! KeyMaterial dispatch helpers.
//!
//! Centralises the three-arm `KeyMaterial` match that selects between
//! `RawKey` → full KDF path, `EncKey` → direct path, and `EncKeys` →
//! salt-lookup + direct path.

use std::path::Path;

use crate::error::DecryptError;
use crate::key_material::KeyMaterial;
use crate::params::CryptoParams;

/// Decrypt a database file, dispatching on the [`KeyMaterial`] variant.
pub fn dispatch_decrypt_db(
    src: &Path,
    dst: &Path,
    km: &KeyMaterial,
    params: &CryptoParams,
) -> Result<(), DecryptError> {
    match km {
        KeyMaterial::RawKey(key) => crate::db::decrypt_db(src, dst, key, params),
        KeyMaterial::EncKey { key, salt } => {
            crate::db::decrypt_db_direct(src, dst, key, salt, params)
        }
        KeyMaterial::EncKeys(pairs) => {
            let db_salt = crate::db::read_main_db_salt_for_path(src)?;
            let pair = pairs
                .iter()
                .find(|p| p.salt == db_salt)
                .ok_or(DecryptError::NoMatchingEncKey)?;
            crate::db::decrypt_db_direct(src, dst, &pair.key, &pair.salt, params)
        }
    }
}

/// Decrypt a WAL file and patch it into the decrypted database,
/// dispatching on the [`KeyMaterial`] variant.
pub fn dispatch_decrypt_wal(
    wal: &Path,
    dst: &Path,
    km: &KeyMaterial,
    params: &CryptoParams,
) -> Result<usize, DecryptError> {
    match km {
        KeyMaterial::RawKey(key) => crate::wal::decrypt_wal(wal, dst, key, params),
        KeyMaterial::EncKey { key, salt } => {
            crate::wal::decrypt_wal_direct(wal, dst, key, salt, params)
        }
        KeyMaterial::EncKeys(pairs) => {
            let db_salt = crate::db::read_main_db_salt_for_path(wal)?;
            let pair = pairs
                .iter()
                .find(|p| p.salt == db_salt)
                .ok_or(DecryptError::NoMatchingEncKey)?;
            crate::wal::decrypt_wal_direct(wal, dst, &pair.key, &pair.salt, params)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_material::EncKeyPair;
    use crate::params::MACOS_4_1_7_31;
    use tempfile::TempDir;

    // ---- helpers ----

    fn derive_enc_key(raw_key: &[u8; 32], salt: &[u8; 16], params: &CryptoParams) -> [u8; 32] {
        let mut key = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<sha2::Sha512>(raw_key, salt, params.kdf_iter, &mut key);
        key
    }

    /// Build a single-page encrypted DB file that `decrypt_db` can process.
    fn build_encrypted_db(path: &Path, raw_key: &[u8; 32], salt: &[u8; 16], params: &CryptoParams) {
        use aes::cipher::{BlockModeEncrypt, KeyIvInit};
        use hmac::{Hmac, Mac};
        use sha2::Sha512;

        let enc_key = derive_enc_key(raw_key, salt, params);
        let mut mac_salt = [0u8; 16];
        for (i, b) in salt.iter().enumerate() {
            mac_salt[i] = b ^ 0x3a;
        }
        let mut mac_key = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<sha2::Sha512>(&enc_key, &mac_salt, 2, &mut mac_key);

        let iv = [0x42u8; 16];
        let data_size = params.page_size - params.reserve - params.salt_size;
        let plaintext = vec![0u8; data_size];

        let mut ciphertext = plaintext;
        type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
        Aes256CbcEnc::new((&enc_key).into(), (&iv).into())
            .encrypt_padded::<aes::cipher::block_padding::NoPadding>(&mut ciphertext, data_size)
            .unwrap();

        let mut page = Vec::with_capacity(params.page_size);
        page.extend_from_slice(salt);
        page.extend_from_slice(&ciphertext);
        page.extend_from_slice(&iv);
        page.resize(params.page_size, 0);

        let hmac_data_end = params.page_size - params.reserve + params.iv_size;
        let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(&mac_key).unwrap();
        mac.update(&page[params.salt_size..hmac_data_end]);
        mac.update(&1u32.to_le_bytes());
        let hmac_result = mac.finalize().into_bytes();
        let hmac_start = params.page_size - params.reserve + params.iv_size;
        page[hmac_start..hmac_start + params.hmac_size]
            .copy_from_slice(&hmac_result[..params.hmac_size]);

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, &page).unwrap();
    }

    // ---- dispatch_decrypt_db tests ----

    #[test]
    fn dispatch_db_raw_key() {
        let raw_key = [0xABu8; 32];
        let salt = [0x01u8; 16];
        let params = &MACOS_4_1_7_31;

        let tmp = TempDir::new().unwrap();
        let src = tmp.path().join("test.db");
        let dst = tmp.path().join("out.db");
        build_encrypted_db(&src, &raw_key, &salt, params);

        let km = KeyMaterial::RawKey(raw_key);
        dispatch_decrypt_db(&src, &dst, &km, params).unwrap();

        let data = std::fs::read(&dst).unwrap();
        assert_eq!(&data[..16], b"SQLite format 3\0");
    }

    #[test]
    fn dispatch_db_enc_key() {
        let raw_key = [0xABu8; 32];
        let salt = [0x01u8; 16];
        let params = &MACOS_4_1_7_31;
        let enc_key = derive_enc_key(&raw_key, &salt, params);

        let tmp = TempDir::new().unwrap();
        let src = tmp.path().join("test.db");
        let dst = tmp.path().join("out.db");
        build_encrypted_db(&src, &raw_key, &salt, params);

        let km = KeyMaterial::EncKey { key: enc_key, salt };
        dispatch_decrypt_db(&src, &dst, &km, params).unwrap();

        let data = std::fs::read(&dst).unwrap();
        assert_eq!(&data[..16], b"SQLite format 3\0");
    }

    #[test]
    fn dispatch_db_enc_keys() {
        let raw_key = [0xABu8; 32];
        let salt1 = [0x01u8; 16];
        let salt2 = [0x02u8; 16];
        let params = &MACOS_4_1_7_31;
        let enc_key1 = derive_enc_key(&raw_key, &salt1, params);
        let enc_key2 = derive_enc_key(&raw_key, &salt2, params);

        let tmp = TempDir::new().unwrap();
        // DB with salt1
        let src = tmp.path().join("test.db");
        let dst = tmp.path().join("out.db");
        build_encrypted_db(&src, &raw_key, &salt1, params);

        let km = KeyMaterial::EncKeys(vec![
            EncKeyPair {
                key: enc_key2,
                salt: salt2,
            },
            EncKeyPair {
                key: enc_key1,
                salt: salt1,
            },
        ]);
        dispatch_decrypt_db(&src, &dst, &km, params).unwrap();

        let data = std::fs::read(&dst).unwrap();
        assert_eq!(&data[..16], b"SQLite format 3\0");
    }

    #[test]
    fn dispatch_db_enc_keys_no_match() {
        let raw_key = [0xABu8; 32];
        let salt_db = [0x01u8; 16];
        let salt_wrong = [0x99u8; 16];
        let params = &MACOS_4_1_7_31;
        let enc_key_wrong = derive_enc_key(&raw_key, &salt_wrong, params);

        let tmp = TempDir::new().unwrap();
        let src = tmp.path().join("test.db");
        let dst = tmp.path().join("out.db");
        build_encrypted_db(&src, &raw_key, &salt_db, params);

        let km = KeyMaterial::EncKeys(vec![EncKeyPair {
            key: enc_key_wrong,
            salt: salt_wrong,
        }]);
        let err = dispatch_decrypt_db(&src, &dst, &km, params).unwrap_err();
        assert!(matches!(err, DecryptError::NoMatchingEncKey));
    }

    // ---- dispatch_decrypt_wal tests ----

    #[test]
    fn dispatch_wal_raw_key_no_frames() {
        let raw_key = [0xABu8; 32];
        let salt = [0x01u8; 16];
        let params = &MACOS_4_1_7_31;

        let tmp = TempDir::new().unwrap();
        // Build a decrypted DB first
        let enc_db = tmp.path().join("enc.db");
        let dec_db = tmp.path().join("dec.db");
        build_encrypted_db(&enc_db, &raw_key, &salt, params);
        crate::db::decrypt_db(&enc_db, &dec_db, &raw_key, params).unwrap();

        // Create a minimal WAL with header only (no frames)
        let wal = tmp.path().join("enc.db-wal");
        let mut wal_header = [0u8; 32];
        wal_header[0..4].copy_from_slice(&0x377f_0682u32.to_be_bytes());
        std::fs::write(&wal, wal_header).unwrap();

        let km = KeyMaterial::RawKey(raw_key);
        let n = dispatch_decrypt_wal(&wal, &dec_db, &km, params).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn dispatch_wal_enc_key_no_frames() {
        let raw_key = [0xABu8; 32];
        let salt = [0x01u8; 16];
        let params = &MACOS_4_1_7_31;
        let enc_key = derive_enc_key(&raw_key, &salt, params);

        let tmp = TempDir::new().unwrap();
        let enc_db = tmp.path().join("enc.db");
        let dec_db = tmp.path().join("dec.db");
        build_encrypted_db(&enc_db, &raw_key, &salt, params);
        crate::db::decrypt_db(&enc_db, &dec_db, &raw_key, params).unwrap();

        let wal = tmp.path().join("enc.db-wal");
        let mut wal_header = [0u8; 32];
        wal_header[0..4].copy_from_slice(&0x377f_0682u32.to_be_bytes());
        std::fs::write(&wal, wal_header).unwrap();

        let km = KeyMaterial::EncKey { key: enc_key, salt };
        let n = dispatch_decrypt_wal(&wal, &dec_db, &km, params).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn dispatch_wal_enc_keys_no_frames() {
        let raw_key = [0xABu8; 32];
        let salt = [0x01u8; 16];
        let params = &MACOS_4_1_7_31;
        let enc_key = derive_enc_key(&raw_key, &salt, params);

        let tmp = TempDir::new().unwrap();
        let enc_db = tmp.path().join("enc.db");
        let dec_db = tmp.path().join("dec.db");
        build_encrypted_db(&enc_db, &raw_key, &salt, params);
        crate::db::decrypt_db(&enc_db, &dec_db, &raw_key, params).unwrap();

        let wal = tmp.path().join("enc.db-wal");
        let mut wal_header = [0u8; 32];
        wal_header[0..4].copy_from_slice(&0x377f_0682u32.to_be_bytes());
        std::fs::write(&wal, wal_header).unwrap();

        let km = KeyMaterial::EncKeys(vec![EncKeyPair { key: enc_key, salt }]);
        let n = dispatch_decrypt_wal(&wal, &dec_db, &km, params).unwrap();
        assert_eq!(n, 0);
    }
}
