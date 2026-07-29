/// A pre-derived encryption key paired with its DB salt.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EncKeyPair {
    pub key: [u8; 32],
    pub salt: [u8; 16],
}

/// Represents either a raw LLDB-extracted key or a pre-derived encryption key
/// found via Mach VM memory scanning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyMaterial {
    /// 32-byte raw key from LLDB capture; requires full PBKDF2 derivation.
    RawKey([u8; 32]),
    /// Pre-derived encryption key + DB salt; skips the 256K-iteration PBKDF2.
    EncKey { key: [u8; 32], salt: [u8; 16] },
    /// Multiple pre-derived enc_keys, each paired with a different DB salt.
    /// Used when `key scan` finds keys for multiple DBs within the same account.
    EncKeys(Vec<EncKeyPair>),
}
