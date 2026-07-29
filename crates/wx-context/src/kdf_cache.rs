use std::collections::HashMap;

use wx_decrypt::{CryptoParams, EncKeyPair};

/// In-memory cache for PBKDF2-derived encryption keys, keyed by DB salt.
///
/// Tracks which entries were derived during the current session (vs pre-loaded)
/// so callers can persist only the new derivations.
pub(crate) struct KdfCache {
    /// salt → enc_key
    entries: HashMap<[u8; 16], [u8; 32]>,
    /// Salts derived this session (not pre-loaded).
    newly_derived: Vec<[u8; 16]>,
}

impl KdfCache {
    /// Pre-load from existing `EncKeyPair`s; `newly_derived` starts empty.
    pub fn from_pairs(pairs: &[EncKeyPair]) -> Self {
        let entries = pairs
            .iter()
            .map(|p| (p.salt, p.key))
            .collect::<HashMap<_, _>>();
        Self {
            entries,
            newly_derived: Vec::new(),
        }
    }

    /// Empty cache with no pre-loaded entries.
    pub fn empty() -> Self {
        Self {
            entries: HashMap::new(),
            newly_derived: Vec::new(),
        }
    }

    /// Cache hit check (returns owned copy).
    pub fn lookup(&self, salt: &[u8; 16]) -> Option<[u8; 32]> {
        self.entries.get(salt).copied()
    }

    /// Lookup; on miss, derive enc_key via PBKDF2, insert to entries,
    /// push salt to `newly_derived`.
    pub fn get_or_derive(
        &mut self,
        salt: &[u8; 16],
        raw_key: &[u8; 32],
        params: &CryptoParams,
    ) -> [u8; 32] {
        if let Some(enc_key) = self.entries.get(salt) {
            return *enc_key;
        }
        let enc_key = wx_decrypt::kdf::derive_enc_key(raw_key, salt, params);
        self.entries.insert(*salt, enc_key);
        self.newly_derived.push(*salt);
        enc_key
    }

    /// Overwrite an entry (for stale enc_key refresh).
    /// Also marks as newly derived if not already tracked.
    pub fn insert(&mut self, salt: &[u8; 16], enc_key: &[u8; 32]) {
        self.entries.insert(*salt, *enc_key);
        if !self.newly_derived.contains(salt) {
            self.newly_derived.push(*salt);
        }
    }

    /// Any new pairs to write back?
    pub fn has_new_derivations(&self) -> bool {
        !self.newly_derived.is_empty()
    }

    /// Only the session-derived pairs (filtered by `newly_derived`).
    #[allow(dead_code)] // Used in tests; will be used by future consumers
    pub fn new_pairs(&self) -> Vec<EncKeyPair> {
        self.newly_derived
            .iter()
            .filter_map(|salt| {
                self.entries.get(salt).map(|key| EncKeyPair {
                    key: *key,
                    salt: *salt,
                })
            })
            .collect()
    }

    /// All entries (for merged writeback).
    pub fn all_pairs(&self) -> Vec<EncKeyPair> {
        self.entries
            .iter()
            .map(|(salt, key)| EncKeyPair {
                key: *key,
                salt: *salt,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wx_decrypt::MACOS_4_1_7_31;

    fn make_pair(salt_byte: u8, key_byte: u8) -> EncKeyPair {
        EncKeyPair {
            salt: [salt_byte; 16],
            key: [key_byte; 32],
        }
    }

    #[test]
    fn pre_load_from_pairs_lookup_hits() {
        let pair = make_pair(0x01, 0xAA);
        let cache = KdfCache::from_pairs(std::slice::from_ref(&pair));

        assert_eq!(cache.lookup(&[0x01; 16]), Some([0xAA; 32]));
        assert_eq!(cache.lookup(&[0x02; 16]), None);
        assert!(!cache.has_new_derivations());
    }

    #[test]
    fn empty_cache_miss_triggers_derive() {
        let mut cache = KdfCache::empty();
        let raw_key = [0xBB; 32];
        let salt = [0x01; 16];

        // Miss → derive
        assert_eq!(cache.lookup(&salt), None);
        let enc_key = cache.get_or_derive(&salt, &raw_key, &MACOS_4_1_7_31);

        // Second lookup hits
        assert_eq!(cache.lookup(&salt), Some(enc_key));
        assert!(cache.has_new_derivations());

        // Verify derivation matches direct call
        let expected = wx_decrypt::kdf::derive_enc_key(&raw_key, &salt, &MACOS_4_1_7_31);
        assert_eq!(enc_key, expected);
    }

    #[test]
    fn new_pairs_only_includes_derived() {
        let preloaded = make_pair(0x01, 0xAA);
        let mut cache = KdfCache::from_pairs(&[preloaded]);

        // Derive a new entry
        let raw_key = [0xCC; 32];
        let new_salt = [0x02; 16];
        cache.get_or_derive(&new_salt, &raw_key, &MACOS_4_1_7_31);

        let new_pairs = cache.new_pairs();
        assert_eq!(new_pairs.len(), 1);
        assert_eq!(new_pairs[0].salt, new_salt);

        // all_pairs includes both
        assert_eq!(cache.all_pairs().len(), 2);
    }

    #[test]
    fn get_or_derive_same_salt_twice_derives_once() {
        let mut cache = KdfCache::empty();
        let raw_key = [0xDD; 32];
        let salt = [0x03; 16];

        let first = cache.get_or_derive(&salt, &raw_key, &MACOS_4_1_7_31);
        let second = cache.get_or_derive(&salt, &raw_key, &MACOS_4_1_7_31);

        assert_eq!(first, second);
        assert_eq!(cache.new_pairs().len(), 1);
    }
}
