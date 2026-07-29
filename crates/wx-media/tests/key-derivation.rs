use wx_media::key::{derive_v2_key_from_dir, read_uin};
use wx_media::{derive_v2_aes_key, extract_wxid};

// ── V2 key derivation formula ──────────────────────────────────────

#[test]
fn derive_v2_key_known_account() {
    // Verified: MD5("1234567890wxid_example123abc") → hex[:16] = d5b763f94307be38
    let key = derive_v2_aes_key("1234567890", "wxid_example123abc");
    assert_eq!(&key, b"d5b763f94307be38");
}

#[test]
fn v1_fixed_key_same_formula() {
    // V1 fixed key = MD5("0")[:16] = cfcd208495d565ef
    let key = derive_v2_aes_key("", "0");
    assert_eq!(&key, b"cfcd208495d565ef");
}

// ── WXID suffix stripping (shared via wx-keychain AccountId) ───

#[test]
fn extract_wxid_strips_suffix() {
    assert_eq!(
        extract_wxid("wxid_example123abc_ab12"),
        "wxid_example123abc"
    );
}

#[test]
fn extract_wxid_no_suffix() {
    assert_eq!(extract_wxid("wxid_example123abc"), "wxid_example123abc");
}

#[test]
fn extract_wxid_long_suffix_not_stripped() {
    assert_eq!(extract_wxid("wxid_test_abcde"), "wxid_test_abcde");
}

#[test]
fn extract_wxid_non_alnum_suffix_not_stripped() {
    assert_eq!(extract_wxid("wxid_test_ab-c"), "wxid_test_ab-c");
}

#[test]
fn extract_wxid_bare_id_not_shortened() {
    // Regression: wxid_test must NOT be shortened to "wxid"
    assert_eq!(extract_wxid("wxid_test"), "wxid_test");
}

#[test]
fn extract_wxid_legacy_non_wxid_without_signal_stays_raw() {
    assert_eq!(extract_wxid("testuser001_1662"), "testuser001_1662");
}

// ── Base64 UIN parsing ─────────────────────────────────────────────

#[test]
fn read_uin_from_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("wxid_test1234_ab12");
    let config_dir = data_dir.join("app_data/radium/ilink/somehash/kvcomm");
    std::fs::create_dir_all(&config_dir).unwrap();
    std::fs::write(
        config_dir.join("config.ini"),
        "[General]\nlast_uin=MTIzNDU2Nzg5MA==\n",
    )
    .unwrap();

    let uin = read_uin(&data_dir).unwrap();
    assert_eq!(uin, "1234567890");
}

#[test]
fn read_uin_no_ilink_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("wxid_test_ab12");
    std::fs::create_dir_all(&data_dir).unwrap();
    assert!(read_uin(&data_dir).is_err());
}

#[test]
fn read_uin_documents_level_path() {
    // Simulate macOS layout: Documents/app_data/ + Documents/xwechat_files/<account>/
    let tmp = tempfile::tempdir().unwrap();
    let docs = tmp.path().join("Documents");
    let data_dir = docs.join("xwechat_files/wxid_example123abc_ab12");
    std::fs::create_dir_all(&data_dir).unwrap();

    let config_dir = docs.join("app_data/radium/ilink/ab12000000000000/kvcomm");
    std::fs::create_dir_all(&config_dir).unwrap();
    std::fs::write(
        config_dir.join("config.ini"),
        "[default]\nlast_uin=MTIzNDU2Nzg5MA==\n",
    )
    .unwrap();

    let uin = read_uin(&data_dir).unwrap();
    assert_eq!(uin, "1234567890");
}

#[test]
fn read_uin_suffix_disambiguation() {
    // Two accounts under ilink — suffix selects the right one
    let tmp = tempfile::tempdir().unwrap();
    let docs = tmp.path().join("Documents");
    let data_dir = docs.join("xwechat_files/wxid_example123abc_ab12");
    std::fs::create_dir_all(&data_dir).unwrap();

    // ab12 account → UIN 1234567890
    let ab12_dir = docs.join("app_data/radium/ilink/ab12000000000000/kvcomm");
    std::fs::create_dir_all(&ab12_dir).unwrap();
    std::fs::write(ab12_dir.join("config.ini"), "last_uin=MTIzNDU2Nzg5MA==\n").unwrap();

    // c3e7 account → UIN 9999999999
    let c3e7_dir = docs.join("app_data/radium/ilink/c3e7000000000000/kvcomm");
    std::fs::create_dir_all(&c3e7_dir).unwrap();
    std::fs::write(
        c3e7_dir.join("config.ini"),
        "last_uin=OTk5OTk5OTk5OQ==\n", // base64("9999999999")
    )
    .unwrap();

    let uin = read_uin(&data_dir).unwrap();
    assert_eq!(uin, "1234567890"); // ab12 suffix → picks ab12 config
}

// ── Full derive_v2_key_from_dir ────────────────────────────────────

#[test]
fn derive_v2_key_from_dir_integration() {
    let tmp = tempfile::tempdir().unwrap();
    let data_dir = tmp.path().join("wxid_example123abc_ab12");
    let config_dir = data_dir.join("app_data/radium/ilink/somehash/kvcomm");
    std::fs::create_dir_all(&config_dir).unwrap();
    std::fs::write(
        config_dir.join("config.ini"),
        "[General]\nlast_uin=MTIzNDU2Nzg5MA==\n",
    )
    .unwrap();

    let key = derive_v2_key_from_dir(&data_dir).unwrap();
    assert_eq!(&key, b"d5b763f94307be38");
}

#[test]
fn derive_v2_key_from_dir_legacy_account_with_login_signal() {
    let tmp = tempfile::tempdir().unwrap();
    let docs = tmp.path().join("Documents");
    let data_dir = docs.join("xwechat_files/testuser001_1662");
    let config_dir = docs.join("app_data/radium/ilink/1662000000000000/kvcomm");
    std::fs::create_dir_all(&config_dir).unwrap();
    std::fs::create_dir_all(docs.join("xwechat_files/all_users/login/testuser001")).unwrap();
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::write(
        config_dir.join("config.ini"),
        "[General]\nlast_uin=MTIzNDU2Nzg5MA==\n",
    )
    .unwrap();

    let key = derive_v2_key_from_dir(&data_dir).unwrap();
    let expected = derive_v2_aes_key("1234567890", "testuser001");
    assert_eq!(key, expected);
}
