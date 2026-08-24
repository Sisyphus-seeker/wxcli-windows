use crate::util::{lookup_or_resolve_nickname, parse_hex_key_32};
pub async fn cmd_key_extract(_timeout_secs: u64) -> Result<(), Box<dyn std::error::Error>> {
    let version = wx_keychain::installed_weixin_version()?;
    let accounts = wx_keychain::find_account_dirs()?;
    if accounts.is_empty() {
        return Err("no WeChat account directories found".into());
    }

    let params = wx_decrypt::platform_default_params();
    let pids = wx_keychain::find_weixin_pids()?;
    eprintln!(
        "Scanning {} Weixin process{} for pre-derived database keys...",
        pids.len(),
        if pids.len() == 1 { "" } else { "es" }
    );
    let results = wx_keychain::capture_keys_windows(&pids, &accounts, params)?;
    persist_scan_results(results, &version)
}

pub fn cmd_key_scan() -> Result<(), Box<dyn std::error::Error>> {
    wx_keychain::preflight_checks()?;
    let (_, version) = wx_keychain::find_wechat_pid()?;
    let pids = wx_keychain::find_weixin_pids()?;
    eprintln!(
        "Found {} Weixin process{} (v{version})",
        pids.len(),
        if pids.len() == 1 { "" } else { "es" }
    );
    let accounts = wx_keychain::find_account_dirs()?;
    if accounts.is_empty() {
        return Err("no WeChat account directories found".into());
    }
    eprintln!(
        "Found {} account director{}",
        accounts.len(),
        if accounts.len() == 1 { "y" } else { "ies" }
    );
    eprintln!("Scanning Weixin process memory...");
    let results =
        wx_keychain::capture_keys_windows(&pids, &accounts, wx_decrypt::platform_default_params())?;
    persist_scan_results(results, &version)
}

fn persist_scan_results(
    results: Vec<wx_keychain::memory_scan::MemoryCaptureResult>,
    version: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Count total pairs across all results
    let total_pairs: usize = results
        .iter()
        .map(|r| match &r.key_material {
            wx_decrypt::KeyMaterial::EncKeys(pairs) => pairs.len(),
            _ => unreachable!("memory capture always returns EncKeys"),
        })
        .sum();
    eprintln!(
        "Found {} valid key{} for {} account{}",
        total_pairs,
        if total_pairs == 1 { "" } else { "s" },
        results.len(),
        if results.len() == 1 { "" } else { "s" },
    );

    // Store results.
    let mut store = wx_keychain::KeyStore::load_default()?;
    for r in &results {
        let matched = &r.matched_account;

        let nickname =
            wx_keychain::resolve_nickname(&matched.data_dir, &r.key_material, &matched.base_wxid)
                .unwrap_or_else(|e| {
                    eprintln!(
                        "  Warning: nickname resolution failed for {}: {e}",
                        matched.account_id
                    );
                    None
                });

        let pairs = match &r.key_material {
            wx_decrypt::KeyMaterial::EncKeys(pairs) => pairs,
            _ => unreachable!("memory capture always returns EncKeys"),
        };

        let mut merged_pairs = pairs.clone();
        if let Some(existing) = store.get(&matched.account_id) {
            merged_pairs.extend(existing.enc_keys.iter().filter_map(|entry| {
                let key = <[u8; 32]>::try_from(hex::decode(&entry.enc_key).ok()?).ok()?;
                let salt = <[u8; 16]>::try_from(hex::decode(&entry.salt).ok()?).ok()?;
                Some(wx_decrypt::EncKeyPair { key, salt })
            }));
        }
        merged_pairs.sort_by(|a, b| a.salt.cmp(&b.salt).then_with(|| a.key.cmp(&b.key)));
        merged_pairs.dedup();

        store.set_enc_keys(
            &matched.account_id,
            &merged_pairs,
            version,
            nickname.clone(),
            Some(matched.base_wxid.clone()),
        );

        let display = nickname
            .as_ref()
            .map(|n| format!("{} ({})", matched.account_id, n))
            .unwrap_or_else(|| matched.account_id.clone());
        eprintln!(
            "  {} — {} enc_key{} stored",
            display,
            merged_pairs.len(),
            if merged_pairs.len() == 1 { "" } else { "s" }
        );
        for pair in pairs {
            println!(
                "{}\t{}\t{}",
                matched.account_id,
                hex::encode(pair.key),
                hex::encode(pair.salt)
            );
        }
    }

    store.save_default()?;
    eprintln!("Keys saved to {:?}", wx_keychain::KeyStore::default_path()?);

    Ok(())
}

pub fn cmd_key_list() -> Result<(), Box<dyn std::error::Error>> {
    let mut store = wx_keychain::KeyStore::load_default()?;
    if store.accounts.is_empty() {
        eprintln!("No keys stored.");
        return Ok(());
    }

    let accounts = wx_keychain::find_account_dirs().unwrap_or_default();
    let mut store_dirty = false;
    for account in &accounts {
        if lookup_or_resolve_nickname(&mut store, account).is_some() {
            store_dirty = true;
        }
    }
    if store_dirty {
        store.save_default()?;
    }

    let mut ids: Vec<_> = store.accounts.keys().cloned().collect();
    ids.sort();
    for id in ids {
        let key = store
            .get(&id)
            .ok_or_else(|| format!("missing key entry for account {id}"))?;

        let raw_status = if key.data_key.is_empty() { "no" } else { "yes" };
        let enc_count = key.enc_keys.len();
        let has_legacy_enc = key.enc_key.as_ref().is_some_and(|k| !k.is_empty());
        let enc_status = if enc_count > 0 {
            format!("{enc_count}")
        } else if has_legacy_enc {
            "1".to_string()
        } else {
            "no".to_string()
        };
        let img_status = if key.image_aes_key.is_some() {
            "yes"
        } else {
            "no"
        };

        let display_key = if !key.data_key.is_empty() {
            key.data_key.clone()
        } else if enc_count > 0 {
            let first = &key.enc_keys[0].enc_key;
            if enc_count > 1 {
                format!("{} (+{} more)", first, enc_count - 1)
            } else {
                first.clone()
            }
        } else if let Some(ref ek) = key.enc_key {
            ek.clone()
        } else {
            "(no key)".to_string()
        };

        println!(
            "{}  {}  (v{}, {}, raw={} enc={} img={})",
            key.display_name(),
            display_key,
            key.wechat_version,
            key.extracted_at.format("%Y-%m-%d %H:%M:%S UTC"),
            raw_status,
            enc_status,
            img_status,
        );
    }
    Ok(())
}

pub fn cmd_key_set(account: &str, hex_key: &str) -> Result<(), Box<dyn std::error::Error>> {
    parse_hex_key_32(hex_key, "manual key")?;

    let mut store = wx_keychain::KeyStore::load_default()?;
    store.set(account, hex_key, "manual", None, None);
    store.save_default()?;
    eprintln!("Key saved for {account}.");
    Ok(())
}

pub fn cmd_key_set_image(account: &str, image_key: &str) -> Result<(), Box<dyn std::error::Error>> {
    let key_hex = if image_key.len() == 32 && image_key.chars().all(|c| c.is_ascii_hexdigit()) {
        image_key.to_string()
    } else if image_key.len() == 16 && image_key.is_ascii() {
        hex::encode(image_key.as_bytes())
    } else {
        return Err(format!(
            "image key must be 16-byte ASCII string or 32-char hex, got {} chars",
            image_key.len()
        )
        .into());
    };

    let mut store = wx_keychain::KeyStore::load_default()?;
    store.set_image_key(account, &key_hex);
    store.save_default()?;
    eprintln!("Image AES key saved for {account}.");
    Ok(())
}
