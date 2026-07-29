use std::path::{Path, PathBuf};
use tempfile::TempDir;
use wx_context::{DecryptRequest, PersistentCache};

fn build_encrypted_db(
    path: &Path,
    raw_key: &[u8; 32],
    salt: &[u8; 16],
    params: &wx_decrypt::CryptoParams,
) {
    use aes::cipher::{BlockModeEncrypt, KeyIvInit};
    use hmac::{Hmac, Mac};
    use sha2::Sha512;

    let enc_key = wx_decrypt::kdf::derive_enc_key(raw_key, salt, params);
    let mac_key = wx_decrypt::kdf::derive_mac_key(&enc_key, salt, params);

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

fn setup_encrypted_dbs(enc_root: &Path, raw_key: &[u8; 32], salt: &[u8; 16]) {
    let params = &wx_decrypt::MACOS_4_1_7_31;
    let contact_dir = enc_root.join("contact");
    let session_dir = enc_root.join("session");
    let msg_dir = enc_root.join("message");
    std::fs::create_dir_all(&contact_dir).unwrap();
    std::fs::create_dir_all(&session_dir).unwrap();
    std::fs::create_dir_all(&msg_dir).unwrap();

    build_encrypted_db(&contact_dir.join("contact.db"), raw_key, salt, params);
    build_encrypted_db(&session_dir.join("session.db"), raw_key, salt, params);
    build_encrypted_db(&msg_dir.join("message_0.db"), raw_key, salt, params);
    build_encrypted_db(&msg_dir.join("message_1.db"), raw_key, salt, params);
    build_encrypted_db(&msg_dir.join("message_2.db"), raw_key, salt, params);
}

fn make_cache(enc_root: PathBuf, cache_root: PathBuf, raw_key: [u8; 32]) -> PersistentCache {
    PersistentCache::new_for_test(
        cache_root,
        enc_root,
        Some(raw_key),
        &wx_decrypt::MACOS_4_1_7_31,
    )
}

// Slow by design: builds encrypted fixtures and runs the real PBKDF2-backed
// decrypt path. Skip by default for routine cargo test runs.
#[test]
#[ignore = "slow decrypt test; runs real PBKDF2/decrypt path"]
fn contacts_only_decrypts_core_dbs() {
    let tmp = TempDir::new().unwrap();
    let enc_root = tmp.path().join("encrypted");
    let cache_root = tmp.path().join("cache");
    let raw_key = [0xABu8; 32];
    let salt = [0x01u8; 16];

    setup_encrypted_dbs(&enc_root, &raw_key, &salt);
    let cache = make_cache(enc_root, cache_root.clone(), raw_key);

    let stats = DecryptRequest::new().core().execute(&cache).unwrap();

    assert_eq!(stats.decrypted, 2, "only contact.db and session.db");
    assert_eq!(stats.errors, 0);

    assert!(cache_root.join("contact/contact.db").exists());
    assert!(cache_root.join("session/session.db").exists());
    assert!(!cache_root.join("message/message_0.db").exists());
    assert!(!cache_root.join("message/message_1.db").exists());
    assert!(!cache_root.join("message/message_2.db").exists());
}

// Slow by design: builds encrypted fixtures and runs the real PBKDF2-backed
// decrypt path. Skip by default for routine cargo test runs.
#[test]
#[ignore = "slow decrypt test; runs real PBKDF2/decrypt path"]
fn core_plus_selected_shards_decrypts_only_requested_dbs() {
    let tmp = TempDir::new().unwrap();
    let enc_root = tmp.path().join("encrypted");
    let cache_root = tmp.path().join("cache");
    let raw_key = [0xABu8; 32];
    let salt = [0x01u8; 16];

    setup_encrypted_dbs(&enc_root, &raw_key, &salt);
    let cache = make_cache(enc_root, cache_root.clone(), raw_key);

    let stats = DecryptRequest::new()
        .core()
        .shards(&[0, 2])
        .execute(&cache)
        .unwrap();

    assert_eq!(
        stats.decrypted, 4,
        "contact + session + message_0 + message_2"
    );
    assert_eq!(stats.errors, 0);

    assert!(cache_root.join("contact/contact.db").exists());
    assert!(cache_root.join("session/session.db").exists());
    assert!(cache_root.join("message/message_0.db").exists());
    assert!(
        !cache_root.join("message/message_1.db").exists(),
        "shard 1 NOT decrypted"
    );
    assert!(cache_root.join("message/message_2.db").exists());
}

// Slow by design: performs multiple decrypt passes to verify incremental
// caching behavior. Skip by default for routine cargo test runs.
#[test]
#[ignore = "slow decrypt test; runs real PBKDF2/decrypt path"]
fn incremental_decrypt_skips_cached() {
    let tmp = TempDir::new().unwrap();
    let enc_root = tmp.path().join("encrypted");
    let cache_root = tmp.path().join("cache");
    let raw_key = [0xABu8; 32];
    let salt = [0x01u8; 16];

    setup_encrypted_dbs(&enc_root, &raw_key, &salt);
    let cache = make_cache(enc_root, cache_root.clone(), raw_key);

    // First: decrypt core only
    let stats1 = DecryptRequest::new().core().execute(&cache).unwrap();
    assert_eq!(stats1.decrypted, 2);

    // Second: decrypt core + shard 0 → core should be skipped
    let stats2 = DecryptRequest::new()
        .core()
        .shards(&[0])
        .execute(&cache)
        .unwrap();
    assert_eq!(stats2.skipped, 2, "contact + session already cached");
    assert_eq!(stats2.decrypted, 1, "only message_0 newly decrypted");
    assert_eq!(stats2.errors, 0);
}
