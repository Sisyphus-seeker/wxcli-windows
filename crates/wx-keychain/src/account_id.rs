/// Normalized account ID, separating raw directory name from canonical base ID
/// and the optional 4-character directory hash suffix used by WeChat macOS.
///
/// Two levels of canonicalization:
/// - **Conservative** (`base()`): only strips suffix for `wxid_*` prefix accounts
///   where the structure is unambiguous. Safe for arbitrary strings.
/// - **Confirmed** (`confirmed_base()`): strips suffix for non-`wxid_` patterns
///   only when an external signal confirms the base ID candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountId {
    raw: String,
    /// Conservative base: only wxid_* suffix stripped
    conservative_base: String,
    /// Alias candidate derived from a trailing `_XXXX` segment.
    alias_candidate: Option<String>,
    suffix: Option<String>,
}

impl AccountId {
    /// Parse an account directory name into its components.
    ///
    /// Detects the trailing `_XXXX` directory hash suffix (exactly 4 alphanumeric
    /// characters). Conservative `base()` only strips for `wxid_*` accounts;
    /// non-`wxid_` inputs expose the stripped form as an alias candidate and need
    /// an external confirmation signal before canonicalization.
    ///
    /// Rules for `base()` (conservative):
    /// - `wxid_example123abc_ab12` → `wxid_example123abc`
    /// - `testuser001_1662` → `testuser001_1662` (not stripped without confirmation)
    /// - `wxid_test` → `wxid_test`
    /// - `not_a_wxid` → `not_a_wxid`
    ///
    /// Rules for `base_for_account_dir()` (confirmed directory without extra signal):
    /// - `wxid_example123abc_ab12` → `wxid_example123abc`
    /// - `testuser001_1662` → `testuser001_1662`
    /// - `wxid_test` → `wxid_test`
    /// - `not_a_wxid` → `not_a_wxid`
    pub fn parse(dir_name: &str) -> Self {
        if let Some(pos) = dir_name.rfind('_') {
            let tail = &dir_name[pos + 1..];
            let prefix = &dir_name[..pos];

            if tail.len() == 4
                && tail.chars().all(|c| c.is_ascii_alphanumeric())
                && !prefix.is_empty()
            {
                // For wxid_ prefix: only strip if base retains wxid_ + substance
                let wxid_safe = if dir_name.starts_with("wxid_") {
                    prefix.starts_with("wxid_") && prefix.len() > 5
                } else {
                    true
                };

                let conservative_base = if wxid_safe && dir_name.starts_with("wxid_") {
                    prefix.to_string()
                } else {
                    dir_name.to_string()
                };

                let alias_candidate = if wxid_safe {
                    Some(prefix.to_string())
                } else {
                    // Even alias matching should not collapse wxid_test → wxid.
                    None
                };

                return Self {
                    raw: dir_name.to_string(),
                    conservative_base,
                    alias_candidate,
                    suffix: Some(tail.to_string()),
                };
            }
        }

        Self {
            raw: dir_name.to_string(),
            conservative_base: dir_name.to_string(),
            alias_candidate: None,
            suffix: None,
        }
    }

    /// The raw account directory name as-is.
    pub fn raw(&self) -> &str {
        &self.raw
    }

    /// Conservative canonical base: only strips suffix for `wxid_*` prefix accounts.
    /// Safe for arbitrary strings — does not assume the input is a real account directory.
    pub fn base(&self) -> &str {
        &self.conservative_base
    }

    /// Confirmed-dir base without extra signal.
    ///
    /// This remains conservative for non-`wxid_` inputs. Call `confirmed_base()`
    /// with an externally confirmed base-ID hint to canonicalize legacy account IDs.
    pub fn base_for_account_dir(&self) -> &str {
        &self.conservative_base
    }

    /// Alias candidate derived from a trailing `_XXXX` segment.
    ///
    /// For legacy non-`wxid_` IDs this is used for alias matching and can be
    /// promoted to the canonical base only when an external signal confirms it.
    pub fn alias_candidate(&self) -> Option<&str> {
        self.alias_candidate.as_deref()
    }

    /// Canonical base for a confirmed directory, using an independently confirmed
    /// base-ID hint when available.
    pub fn confirmed_base(&self, confirmed_base: Option<&str>) -> &str {
        match (self.alias_candidate(), confirmed_base) {
            (Some(candidate), Some(confirmed)) if candidate == confirmed => candidate,
            _ => self.base_for_account_dir(),
        }
    }

    /// The 4-character directory hash suffix candidate, if detected.
    ///
    /// Present even when the canonical base was NOT stripped (e.g. `wxid_test`
    /// has suffix `Some("test")` but base remains `wxid_test`). Useful for
    /// ilink directory prioritization in media key derivation.
    pub fn suffix(&self) -> Option<&str> {
        self.suffix.as_deref()
    }

    /// Whether the conservative base differs from the raw name.
    pub fn has_stripped_suffix(&self) -> bool {
        self.raw != self.conservative_base
    }

    /// Check if a user-provided token matches this account.
    ///
    /// Matches against raw name, conservative base, and the alias candidate.
    /// This allows `--account testuser001` to match directory `testuser001_1662`.
    pub fn matches(&self, token: &str) -> bool {
        self.raw == token
            || self.conservative_base == token
            || self.alias_candidate.as_deref() == Some(token)
    }
}

/// Convenience: compute conservative canonical base from a directory name.
///
/// Only strips suffix for `wxid_*` prefix accounts. For non-`wxid_` inputs,
/// returns the input unchanged. Use `canonical_base_for_account_dir()` when
/// the input is a confirmed account directory.
pub fn canonical_base(dir_name: &str) -> String {
    AccountId::parse(dir_name).base().to_string()
}

/// Compute canonical base for a confirmed account directory without extra signal.
pub fn canonical_base_for_account_dir(dir_name: &str) -> String {
    AccountId::parse(dir_name)
        .base_for_account_dir()
        .to_string()
}

/// Compute canonical base for a confirmed account directory with an independently
/// confirmed base-ID hint (for example `all_users/login/<base-id>`).
pub fn canonical_base_for_account_dir_with_confirmed_base(
    dir_name: &str,
    confirmed_base: Option<&str>,
) -> String {
    AccountId::parse(dir_name)
        .confirmed_base(confirmed_base)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wxid_with_suffix() {
        let id = AccountId::parse("wxid_example123abc_ab12");
        assert_eq!(id.base(), "wxid_example123abc");
        assert_eq!(id.base_for_account_dir(), "wxid_example123abc");
        assert_eq!(id.alias_candidate(), Some("wxid_example123abc"));
        assert_eq!(id.suffix(), Some("ab12"));
        assert!(id.has_stripped_suffix());
        assert!(id.matches("wxid_example123abc_ab12"));
        assert!(id.matches("wxid_example123abc"));
        assert!(!id.matches("wxid_example"));
    }

    #[test]
    fn legacy_non_wxid_conservative_not_stripped() {
        let id = AccountId::parse("testuser001_1662");
        // Conservative: NOT stripped (no independent signal)
        assert_eq!(id.base(), "testuser001_1662");
        // Confirmed dir without extra signal: still conservative
        assert_eq!(id.base_for_account_dir(), "testuser001_1662");
        assert_eq!(id.alias_candidate(), Some("testuser001"));
        assert_eq!(id.suffix(), Some("1662"));
        assert!(!id.has_stripped_suffix());
        assert!(id.matches("testuser001_1662"));
        assert!(id.matches("testuser001"));
    }

    #[test]
    fn not_a_wxid_conservative_not_stripped() {
        let id = AccountId::parse("not_a_wxid");
        // Conservative: NOT stripped
        assert_eq!(id.base(), "not_a_wxid");
        // Confirmed dir without extra signal: still conservative
        assert_eq!(id.base_for_account_dir(), "not_a_wxid");
        assert_eq!(id.alias_candidate(), Some("not_a"));
        assert_eq!(id.suffix(), Some("wxid"));
    }

    #[test]
    fn wxid_test_not_stripped() {
        let id = AccountId::parse("wxid_test");
        assert_eq!(id.base(), "wxid_test");
        // Even for confirmed dirs, wxid_test → wxid is not safe
        assert_eq!(id.base_for_account_dir(), "wxid_test");
        assert_eq!(id.alias_candidate(), None);
        assert_eq!(id.suffix(), Some("test"));
        assert!(!id.has_stripped_suffix());
    }

    #[test]
    fn wxid_bare_short() {
        let id = AccountId::parse("wxid_x");
        assert_eq!(id.base(), "wxid_x");
        assert_eq!(id.suffix(), None);
    }

    #[test]
    fn long_suffix_not_stripped() {
        let id = AccountId::parse("wxid_test_abcde");
        assert_eq!(id.base(), "wxid_test_abcde");
        assert_eq!(id.suffix(), None);
    }

    #[test]
    fn non_alnum_suffix_not_stripped() {
        let id = AccountId::parse("wxid_test_ab-c");
        assert_eq!(id.base(), "wxid_test_ab-c");
        assert_eq!(id.suffix(), None);
    }

    #[test]
    fn multiple_underscores_wxid() {
        let id = AccountId::parse("wxid_foobar456def_c3e7");
        assert_eq!(id.base(), "wxid_foobar456def");
        assert_eq!(id.suffix(), Some("c3e7"));
        assert!(id.has_stripped_suffix());
    }

    #[test]
    fn no_underscore() {
        let id = AccountId::parse("nounderscore");
        assert_eq!(id.base(), "nounderscore");
        assert_eq!(id.suffix(), None);
    }

    #[test]
    fn bare_wxid_prefix() {
        let id = AccountId::parse("wxid_");
        assert_eq!(id.base(), "wxid_");
        assert_eq!(id.suffix(), None);
    }

    #[test]
    fn canonical_base_conservative() {
        assert_eq!(
            canonical_base("wxid_example123abc_ab12"),
            "wxid_example123abc"
        );
        // Non-wxid: conservative does NOT strip
        assert_eq!(canonical_base("testuser001_1662"), "testuser001_1662");
        assert_eq!(canonical_base("wxid_test"), "wxid_test");
        assert_eq!(canonical_base("not_a_wxid"), "not_a_wxid");
    }

    #[test]
    fn canonical_base_for_account_dir_stays_conservative_for_non_wxid() {
        assert_eq!(
            canonical_base_for_account_dir("wxid_example123abc_ab12"),
            "wxid_example123abc"
        );
        assert_eq!(
            canonical_base_for_account_dir("testuser001_1662"),
            "testuser001_1662"
        );
        // wxid_test is protected: stripping would leave bare "wxid"
        assert_eq!(canonical_base_for_account_dir("wxid_test"), "wxid_test");
        assert_eq!(canonical_base_for_account_dir("not_a_wxid"), "not_a_wxid");
    }

    #[test]
    fn canonical_base_for_account_dir_uses_confirmed_base_hint() {
        assert_eq!(
            canonical_base_for_account_dir_with_confirmed_base(
                "testuser001_1662",
                Some("testuser001")
            ),
            "testuser001"
        );
        assert_eq!(
            canonical_base_for_account_dir_with_confirmed_base("not_a_wxid", Some("not_a")),
            "not_a"
        );
        assert_eq!(
            canonical_base_for_account_dir_with_confirmed_base(
                "testuser001_1662",
                Some("someone_else")
            ),
            "testuser001_1662"
        );
    }
}
