use std::path::{Path, PathBuf};

use wx_decrypt::KeyMaterial;

use crate::ContextError;

pub struct AccountContext {
    pub account_id: String,
    pub base_wxid: String,
    pub data_dir: PathBuf,
    pub key_material: KeyMaterial,
    /// The original 32-byte raw key, always populated when `data_key` exists in the store
    /// or when `--key` is provided via CLI.
    pub raw_key: Option<[u8; 32]>,
    /// Whether KDF cache writeback is allowed. False when `--key` CLI flag is used
    /// (ephemeral key source), true when key comes from KeyStore.
    pub writeback_enabled: bool,
    /// Human-readable note about how the account was resolved (e.g. "Auto-detected account: ...").
    /// The CLI layer should print this; the library itself never writes to stderr.
    pub detection_note: Option<String>,
}

/// 解析参数。三种入口互斥，优先级：account > data_dir > 自动检测。
pub struct ResolveParams<'a> {
    pub account: Option<&'a str>,
    pub data_dir: Option<&'a Path>,
    pub key_hex: Option<&'a str>,
}

impl AccountContext {
    pub fn resolve(params: &ResolveParams<'_>) -> Result<Self, ContextError> {
        let (account_id, base_wxid, data_dir, detection_note) = Self::resolve_account(params)?;
        let (key_material, raw_key, writeback_enabled) =
            Self::resolve_key(params.key_hex, &account_id)?;
        Ok(Self {
            account_id,
            base_wxid,
            data_dir,
            key_material,
            raw_key,
            writeback_enabled,
            detection_note,
        })
    }

    fn resolve_account(
        params: &ResolveParams<'_>,
    ) -> Result<(String, String, PathBuf, Option<String>), ContextError> {
        // 1. --account 指定 → 在已知账号中查找（exact account_id > exact base alias > ambiguity error）
        if let Some(acct) = params.account {
            let accounts = wx_keychain::find_account_dirs()?;

            // Exact account_id match wins
            if let Some(exact) = accounts.iter().find(|a| a.account_id == acct) {
                return Ok((
                    exact.account_id.clone(),
                    exact.base_wxid.clone(),
                    exact.data_dir.clone(),
                    None,
                ));
            }

            // Canonical base alias match (e.g. "testuser001" matches dir "testuser001_1662")
            let alias_matches: Vec<_> = accounts
                .iter()
                .filter(|a| {
                    let id = wx_keychain::AccountId::parse(&a.account_id);
                    id.matches(acct)
                })
                .collect();

            return match alias_matches.len() {
                1 => Ok((
                    alias_matches[0].account_id.clone(),
                    alias_matches[0].base_wxid.clone(),
                    alias_matches[0].data_dir.clone(),
                    None,
                )),
                0 => Err(ContextError::NoAccount(format!("'{acct}' not found"))),
                _ => {
                    let candidates = alias_matches
                        .iter()
                        .map(|a| format!("  - {} (base: {})", a.account_id, a.base_wxid))
                        .collect::<Vec<_>>()
                        .join("\n");
                    Err(ContextError::NoAccount(format!(
                        "ambiguous account '{acct}': multiple directories match\n{candidates}"
                    )))
                }
            };
        }

        // 2. -d 指定
        if let Some(dir) = params.data_dir {
            if wx_keychain::is_xwechat_files_root(dir) {
                // xwechat_files 根目录 → 自动检测活跃账号
                let accounts = wx_keychain::find_account_dirs_under(dir)?;
                if accounts.is_empty() {
                    return Err(ContextError::NoAccount("no account dirs under root".into()));
                }
                let active = wx_keychain::detect_active_account(&accounts)?;
                let note = format!(
                    "Auto-detected account: {} (source: {})",
                    active.info.account_id, active.source
                );
                return Ok((
                    active.info.account_id,
                    active.info.base_wxid,
                    active.info.data_dir,
                    Some(note),
                ));
            }
            // 直接账号目录 — confirmed directory, use aggressive normalization
            let account_id = dir
                .file_name()
                .and_then(|n| n.to_str())
                .ok_or_else(|| ContextError::NoAccount("invalid data_dir".into()))?
                .to_string();
            let base_wxid = dir
                .parent()
                .map(|root| {
                    wx_keychain::process::extract_base_wxid_for_account_dir_under_root(
                        root,
                        &account_id,
                    )
                })
                .unwrap_or_else(|| {
                    wx_keychain::process::extract_base_wxid_for_account_dir(&account_id)
                });
            return Ok((account_id, base_wxid, dir.to_path_buf(), None));
        }

        // 3. 全自动检测
        let accounts = wx_keychain::find_account_dirs()?;
        if accounts.is_empty() {
            return Err(ContextError::NoAccount(
                "no WeChat account directories found; use --data-dir or --account".into(),
            ));
        }
        if accounts.len() == 1 {
            let note = format!("Auto-detected account: {}", accounts[0].account_id);
            let a = accounts.into_iter().next().unwrap();
            return Ok((a.account_id, a.base_wxid, a.data_dir, Some(note)));
        }
        let active = wx_keychain::detect_active_account(&accounts)?;
        let note = format!(
            "Auto-detected account: {} (source: {})",
            active.info.account_id, active.source
        );
        Ok((
            active.info.account_id,
            active.info.base_wxid,
            active.info.data_dir,
            Some(note),
        ))
    }

    /// Returns (key_material, raw_key, writeback_enabled).
    fn resolve_key(
        key_hex: Option<&str>,
        account_id: &str,
    ) -> Result<(KeyMaterial, Option<[u8; 32]>, bool), ContextError> {
        // CLI --key flag always produces a RawKey; writeback disabled (ephemeral source).
        if let Some(h) = key_hex {
            let km = Self::parse_raw_key(h)?;
            let raw = match &km {
                KeyMaterial::RawKey(k) => Some(*k),
                _ => None,
            };
            return Ok((km, raw, false));
        }

        // No CLI key — resolve from KeyStore, preferring raw_key when available.
        let store = wx_keychain::KeyStore::load_default()?;
        Self::resolve_key_with_store(&store, account_id)
    }

    fn resolve_key_with_store(
        store: &wx_keychain::KeyStore,
        account_id: &str,
    ) -> Result<(KeyMaterial, Option<[u8; 32]>, bool), ContextError> {
        let km = Self::resolve_key_from_store(store, account_id)?;

        // Extract raw_key from store entry's data_key field.
        let raw_key = store.get(account_id).and_then(|entry| {
            if entry.data_key.is_empty() {
                return None;
            }
            let bytes = hex::decode(&entry.data_key).ok()?;
            if bytes.len() != 32 {
                return None;
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes);
            Some(key)
        });

        Ok((km, raw_key, true))
    }

    fn parse_raw_key(hex_str: &str) -> Result<KeyMaterial, ContextError> {
        let bytes = hex::decode(hex_str)
            .map_err(|e| ContextError::Cache(format!("invalid hex key: {e}")))?;
        if bytes.len() != 32 {
            return Err(ContextError::Cache(format!(
                "key must be 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        Ok(KeyMaterial::RawKey(key))
    }

    /// Resolve key from store, preferring raw_key when available (covers all DBs).
    ///
    /// The store layer prefers `EncKeys`/`EncKey` (faster decrypt), but at runtime
    /// `RawKey` is more universal — it can decrypt any DB without salt matching.
    fn resolve_key_from_store(
        store: &wx_keychain::KeyStore,
        account_id: &str,
    ) -> Result<KeyMaterial, ContextError> {
        let entry = store
            .get(account_id)
            .ok_or_else(|| ContextError::NoKey(account_id.to_string()))?;

        // Prefer raw_key when available — it covers all DBs.
        if !entry.data_key.is_empty() {
            if let Ok(key_bytes) = hex::decode(&entry.data_key) {
                if key_bytes.len() == 32 {
                    let mut key = [0u8; 32];
                    key.copy_from_slice(&key_bytes);
                    return Ok(KeyMaterial::RawKey(key));
                }
            }
        }

        // Fall back to store's default resolution (EncKeys > EncKey).
        store
            .resolve_key_material(account_id)
            .ok_or_else(|| ContextError::NoKey(account_id.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wx_decrypt::EncKeyPair;

    #[test]
    fn resolve_key_from_store_with_enc_key_only_returns_enc_key() {
        let mut store = wx_keychain::KeyStore::default();
        let enc_key = "ab".repeat(32);
        let enc_salt = "cd".repeat(16);
        store.set_enc_key(
            "wxid_test_1234",
            &enc_key,
            &enc_salt,
            "4.1.7.31",
            None,
            None,
        );

        let km = AccountContext::resolve_key_from_store(&store, "wxid_test_1234").unwrap();
        match km {
            KeyMaterial::EncKey { key, salt } => {
                assert_eq!(hex::encode(key), enc_key);
                assert_eq!(hex::encode(salt), enc_salt);
            }
            _ => panic!("expected EncKey variant when only enc_key exists"),
        }
    }

    #[test]
    fn resolve_key_from_store_raw_key_preferred_over_enc_key() {
        let mut store = wx_keychain::KeyStore::default();
        let data_key = "ef".repeat(32);
        let enc_key = "ab".repeat(32);
        let enc_salt = "cd".repeat(16);
        store.set("wxid_test_1234", &data_key, "4.1.7.31", None, None);
        store.set_enc_key(
            "wxid_test_1234",
            &enc_key,
            &enc_salt,
            "4.1.7.31",
            None,
            None,
        );

        let km = AccountContext::resolve_key_from_store(&store, "wxid_test_1234").unwrap();
        match km {
            KeyMaterial::RawKey(key) => {
                assert_eq!(hex::encode(key), data_key);
            }
            _ => panic!("expected RawKey variant (raw_key should be preferred)"),
        }
    }

    #[test]
    fn resolve_key_from_store_raw_key_preferred_over_enc_keys() {
        let mut store = wx_keychain::KeyStore::default();
        let data_key = "ef".repeat(32);
        store.set("wxid_test_1234", &data_key, "4.1.7.31", None, None);

        let pairs = vec![
            EncKeyPair {
                key: [0xAAu8; 32],
                salt: [0x01u8; 16],
            },
            EncKeyPair {
                key: [0xBBu8; 32],
                salt: [0x02u8; 16],
            },
        ];
        store.set_enc_keys("wxid_test_1234", &pairs, "4.1.8.0", None, None);

        let km = AccountContext::resolve_key_from_store(&store, "wxid_test_1234").unwrap();
        match km {
            KeyMaterial::RawKey(key) => {
                assert_eq!(hex::encode(key), data_key);
            }
            _ => panic!("expected RawKey variant (raw_key should be preferred over EncKeys)"),
        }
    }

    #[test]
    fn resolve_key_from_store_with_data_key_only_returns_raw_key() {
        let mut store = wx_keychain::KeyStore::default();
        let data_key = "ef".repeat(32);
        store.set("wxid_test_1234", &data_key, "4.1.7.31", None, None);

        let km = AccountContext::resolve_key_from_store(&store, "wxid_test_1234").unwrap();
        match km {
            KeyMaterial::RawKey(key) => {
                assert_eq!(hex::encode(key), data_key);
            }
            _ => panic!("expected RawKey variant"),
        }
    }

    #[test]
    fn resolve_key_from_store_enc_keys_only_returns_enc_keys() {
        let mut store = wx_keychain::KeyStore::default();
        let pairs = vec![EncKeyPair {
            key: [0xAAu8; 32],
            salt: [0x01u8; 16],
        }];
        store.set_enc_keys("wxid_test_1234", &pairs, "4.1.8.0", None, None);

        let km = AccountContext::resolve_key_from_store(&store, "wxid_test_1234").unwrap();
        assert!(matches!(km, KeyMaterial::EncKeys(_)));
    }

    #[test]
    fn resolve_key_with_key_hex_always_returns_raw_key() {
        let hex_key = "ab".repeat(32);
        let km = AccountContext::parse_raw_key(&hex_key).unwrap();
        match km {
            KeyMaterial::RawKey(key) => {
                assert_eq!(hex::encode(key), hex_key);
            }
            _ => panic!("expected RawKey variant"),
        }
    }

    #[test]
    fn resolve_key_from_store_missing_account_returns_error() {
        let store = wx_keychain::KeyStore::default();
        let result = AccountContext::resolve_key_from_store(&store, "wxid_nonexistent");
        assert!(result.is_err());
    }

    #[test]
    fn resolve_key_raw_key_populated_when_data_key_exists() {
        let data_key = "ab".repeat(32);
        let account_id = "wxid_test_kdf_cache";
        let mut store = wx_keychain::KeyStore::default();
        store.set(account_id, &data_key, "4.1.7.31", None, None);

        let (km, raw_key, writeback_enabled) =
            AccountContext::resolve_key_with_store(&store, account_id).unwrap();
        assert!(
            matches!(km, KeyMaterial::RawKey(_)),
            "should resolve as RawKey"
        );
        assert!(
            raw_key.is_some(),
            "raw_key should be populated when data_key exists in store"
        );
        assert_eq!(hex::encode(raw_key.unwrap()), data_key);
        assert!(
            writeback_enabled,
            "writeback should be true when key comes from KeyStore"
        );
    }

    #[test]
    fn resolve_key_writeback_disabled_when_key_hex_provided() {
        let hex_key = "cd".repeat(32);
        let (_km, raw_key, writeback_enabled) =
            AccountContext::resolve_key(Some(&hex_key), "wxid_test").unwrap();
        assert!(raw_key.is_some(), "raw_key should be populated from --key");
        assert!(
            !writeback_enabled,
            "writeback_enabled must be false for CLI --key path"
        );
    }

    // ── resolve_account alias matching tests ──────────────────────────

    fn make_account_dir(
        root: &std::path::Path,
        name: &str,
        confirmed_base: Option<&str>,
    ) -> wx_keychain::AccountDirInfo {
        let dir = root.join(name);
        let db_dir = dir.join("db_storage/message");
        std::fs::create_dir_all(&db_dir).unwrap();
        std::fs::write(db_dir.join("message_0.db"), b"fake").unwrap();
        if let Some(base) = confirmed_base {
            std::fs::create_dir_all(root.join("all_users/login").join(base)).unwrap();
        }
        wx_keychain::find_account_dirs_under(root)
            .unwrap()
            .into_iter()
            .find(|a| a.account_id == name)
            .unwrap()
    }

    #[test]
    fn resolve_account_alias_matches_legacy_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let acct = make_account_dir(tmp.path(), "testuser001_1662", Some("testuser001"));

        // base_wxid should be canonicalized for confirmed dir
        assert_eq!(acct.base_wxid, "testuser001");

        // AccountId::matches should find it via the base alias
        let id = wx_keychain::AccountId::parse(&acct.account_id);
        assert!(id.matches("testuser001"), "alias should match");
        assert!(id.matches("testuser001_1662"), "raw should match");
    }

    #[test]
    fn resolve_account_alias_ambiguity_detected() {
        let tmp = tempfile::tempdir().unwrap();
        // Two directories that share the same base alias
        make_account_dir(tmp.path(), "user123_ab12", None);
        make_account_dir(tmp.path(), "user123_cd34", None);

        let accounts = wx_keychain::find_account_dirs_under(tmp.path()).unwrap();
        assert_eq!(accounts.len(), 2);

        // Both should match "user123"
        let matches: Vec<_> = accounts
            .iter()
            .filter(|a| {
                let id = wx_keychain::AccountId::parse(&a.account_id);
                id.matches("user123")
            })
            .collect();

        assert_eq!(
            matches.len(),
            2,
            "ambiguity: two dirs share the same base alias"
        );
    }

    #[test]
    fn resolve_account_exact_id_takes_priority() {
        let tmp = tempfile::tempdir().unwrap();
        make_account_dir(tmp.path(), "wxid_foo123_ab12", None);

        let accounts = wx_keychain::find_account_dirs_under(tmp.path()).unwrap();
        let exact = accounts.iter().find(|a| a.account_id == "wxid_foo123_ab12");
        assert!(exact.is_some(), "exact account_id match should be found");
    }

    #[test]
    fn resolve_account_data_dir_keeps_legacy_dir_without_login_hint() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("testuser001_1662");
        std::fs::create_dir_all(&dir).unwrap();

        let (account_id, base_wxid, resolved_dir, note) =
            AccountContext::resolve_account(&ResolveParams {
                account: None,
                data_dir: Some(&dir),
                key_hex: None,
            })
            .unwrap();

        assert_eq!(account_id, "testuser001_1662");
        assert_eq!(base_wxid, "testuser001_1662");
        assert_eq!(resolved_dir, dir);
        assert_eq!(note, None);
    }
}
