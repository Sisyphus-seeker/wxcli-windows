pub fn cmd_status() -> Result<(), Box<dyn std::error::Error>> {
    // WeChat process status (pgrep-only, no lsof)
    match wx_keychain::find_wechat_pid() {
        Ok((pid, version)) => {
            println!("WeChat:   running (pid {pid}, v{version})");
        }
        Err(_) => {
            println!("WeChat:   not running");
        }
    }

    // Account directories
    let accounts = wx_keychain::find_account_dirs().unwrap_or_default();
    let store = wx_keychain::KeyStore::load_default().unwrap_or_default();

    if accounts.is_empty() {
        println!("Accounts: (none found)");
    } else {
        println!("Accounts:");
        for a in &accounts {
            let key_entry = store.get(&a.account_id);
            let has_key = key_entry.is_some();

            // Display name from KeyStore
            let display = key_entry
                .and_then(|k| k.nickname.as_deref())
                .map(|n| format!(" ({n})"))
                .unwrap_or_default();

            let key_icon = if has_key { "\u{2705}" } else { "\u{2717}" };

            // Cache status
            let cache_info = cache_status(&a.account_id);

            println!("  {}{display}  key {key_icon}  {cache_info}", a.account_id,);
        }
    }

    // Paths summary
    if let Ok(ap) = wx_paths::AppPaths::new() {
        let config = tilde_path(&ap.config_dir());
        let cache = tilde_path(ap.cache_root());
        println!("Paths:    config {config}  cache {cache}");
    }

    Ok(())
}

fn tilde_path(path: &std::path::Path) -> String {
    if let Ok(home) = std::env::var("HOME") {
        let home_path = std::path::Path::new(&home);
        if let Ok(suffix) = path.strip_prefix(home_path) {
            return format!("~/{}", suffix.display());
        }
    }
    path.display().to_string()
}

fn cache_status(account_id: &str) -> String {
    let cache_dir = match wx_paths::AppPaths::new() {
        Ok(ap) => ap.account_db_cache_dir(account_id),
        Err(_) => return "cache: unknown".into(),
    };

    if !cache_dir.exists() {
        return "no cache".into();
    }

    // Count .db files and find most recent mtime
    let mut db_count = 0usize;
    let mut newest = std::time::SystemTime::UNIX_EPOCH;

    if let Ok(entries) = std::fs::read_dir(&cache_dir) {
        for entry in entries.flatten() {
            count_db_files_recursive(&entry.path(), &mut db_count, &mut newest);
        }
    }

    if db_count == 0 {
        return "cache empty".into();
    }

    let age = newest
        .elapsed()
        .map(format_duration)
        .unwrap_or_else(|_| "?".into());

    format!("{db_count} DBs  last decrypt {age} ago")
}

fn count_db_files_recursive(
    path: &std::path::Path,
    count: &mut usize,
    newest: &mut std::time::SystemTime,
) {
    if path.is_dir() {
        if let Ok(entries) = std::fs::read_dir(path) {
            for entry in entries.flatten() {
                count_db_files_recursive(&entry.path(), count, newest);
            }
        }
    } else if path.extension().is_some_and(|e| e == "db") {
        *count += 1;
        if let Ok(meta) = path.metadata() {
            if let Ok(mtime) = meta.modified() {
                if mtime > *newest {
                    *newest = mtime;
                }
            }
        }
    }
}

fn format_duration(d: std::time::Duration) -> String {
    let secs = d.as_secs();
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else if secs < 86400 {
        format!("{}h", secs / 3600)
    } else {
        format!("{}d", secs / 86400)
    }
}
