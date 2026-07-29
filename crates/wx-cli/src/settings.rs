use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// Per-account visibility settings loaded from `<config_dir>/settings.toml`.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Settings {
    #[serde(default)]
    pub accounts: BTreeMap<String, AccountSettings>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AccountSettings {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ignore_contacts: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ignore_tags: Vec<String>,
}

impl Settings {
    /// Load from the default path, returning empty settings if the file doesn't exist.
    pub fn load_default() -> Result<Self, Box<dyn std::error::Error>> {
        let ap = wx_paths::AppPaths::new()?;
        ap.migrate_config()?;
        let path = ap.settings_file();
        Self::load(&path)
    }

    /// Load from a specific path, returning empty settings if the file doesn't exist.
    pub fn load(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let content = fs::read_to_string(path)?;
        let settings: Self = toml::from_str(&content)?;
        Ok(settings.sanitize())
    }

    /// Get settings for a specific account, returning empty settings if not configured.
    pub fn for_account(&self, account_id: &str) -> AccountSettings {
        self.accounts.get(account_id).cloned().unwrap_or_default()
    }

    /// Trim whitespace and remove empty strings from all lists.
    fn sanitize(mut self) -> Self {
        for settings in self.accounts.values_mut() {
            settings.ignore_contacts = sanitize_list(&settings.ignore_contacts);
            settings.ignore_tags = sanitize_list(&settings.ignore_tags);
        }
        self
    }
}

fn sanitize_list(items: &[String]) -> Vec<String> {
    items
        .iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_config_returns_defaults() {
        let settings = Settings::default();
        let acct = settings.for_account("wxid_test_ab12");
        assert!(acct.ignore_contacts.is_empty());
        assert!(acct.ignore_tags.is_empty());
    }

    #[test]
    fn loads_account_settings() {
        let toml = r#"
[accounts."wxid_test_ab12"]
ignore_contacts = ["wxid_hidden", "12345@chatroom"]
ignore_tags = ["同事"]
"#;
        let settings: Settings = toml::from_str(toml).unwrap();
        let acct = settings.for_account("wxid_test_ab12");
        assert_eq!(acct.ignore_contacts, vec!["wxid_hidden", "12345@chatroom"]);
        assert_eq!(acct.ignore_tags, vec!["同事"]);
    }

    #[test]
    fn unknown_account_returns_empty() {
        let toml = r#"
[accounts."wxid_other"]
ignore_contacts = ["wxid_hidden"]
"#;
        let settings: Settings = toml::from_str(toml).unwrap();
        let acct = settings.for_account("wxid_test_ab12");
        assert!(acct.ignore_contacts.is_empty());
    }

    #[test]
    fn sanitize_trims_and_removes_empty() {
        let toml = r#"
[accounts."wxid_test"]
ignore_contacts = ["  wxid_a  ", "", "  ", "wxid_b"]
ignore_tags = ["  同事  ", ""]
"#;
        let settings: Settings = toml::from_str::<Settings>(toml).unwrap().sanitize();
        let acct = settings.for_account("wxid_test");
        assert_eq!(acct.ignore_contacts, vec!["wxid_a", "wxid_b"]);
        assert_eq!(acct.ignore_tags, vec!["同事"]);
    }

    #[test]
    fn legacy_removed_field_silently_ignored() {
        // Verify that a TOML with an unknown field (formerly used, now removed)
        // deserializes without error — serde without deny_unknown_fields ignores it.
        let legacy_key = format!("ignore_{}", "senders");
        let toml = format!(
            "[accounts.\"wxid_test\"]\nignore_contacts = [\"wxid_a\"]\n{legacy_key} = [\"wxid_spam\", \"wxid_noisy\"]\n"
        );
        let settings: Settings = toml::from_str(&toml).unwrap();
        let acct = settings.for_account("wxid_test");
        assert_eq!(acct.ignore_contacts, vec!["wxid_a"]);
    }

    #[test]
    fn missing_file_returns_empty() {
        let settings = Settings::load(Path::new("/nonexistent/settings.toml")).unwrap();
        assert!(settings.accounts.is_empty());
    }
}
