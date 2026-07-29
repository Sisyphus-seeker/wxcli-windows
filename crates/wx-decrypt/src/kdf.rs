use pbkdf2::pbkdf2_hmac;
use sha2::Sha512;

use crate::params::CryptoParams;

/// Derive the AES-256 encryption key from the raw key and salt.
///
/// Uses PBKDF2-HMAC-SHA512 with `params.kdf_iter` iterations.
pub fn derive_enc_key(raw_key: &[u8; 32], salt: &[u8; 16], params: &CryptoParams) -> [u8; 32] {
    let mut enc_key = [0u8; 32];
    pbkdf2_hmac::<Sha512>(raw_key, salt, params.kdf_iter, &mut enc_key);
    enc_key
}

/// Derive the HMAC key from the encryption key and salt.
///
/// Uses PBKDF2-HMAC-SHA512 with 2 iterations. The MAC salt is `salt XOR 0x3a`.
pub fn derive_mac_key(enc_key: &[u8; 32], salt: &[u8; 16], _params: &CryptoParams) -> [u8; 32] {
    let mac_salt: [u8; 16] = std::array::from_fn(|i| salt[i] ^ 0x3a);
    let mut mac_key = [0u8; 32];
    pbkdf2_hmac::<Sha512>(enc_key, &mac_salt, 2, &mut mac_key);
    mac_key
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::MACOS_4_1_7_31;

    #[test]
    fn test_derive_keys_deterministic() {
        let raw_key = [0xABu8; 32];
        let salt = [0x01u8; 16];

        let enc1 = derive_enc_key(&raw_key, &salt, &MACOS_4_1_7_31);
        let enc2 = derive_enc_key(&raw_key, &salt, &MACOS_4_1_7_31);
        assert_eq!(enc1, enc2);

        let mac1 = derive_mac_key(&enc1, &salt, &MACOS_4_1_7_31);
        let mac2 = derive_mac_key(&enc2, &salt, &MACOS_4_1_7_31);
        assert_eq!(mac1, mac2);
    }

    #[test]
    fn test_derive_keys_different_salt() {
        let raw_key = [0xABu8; 32];
        let salt_a = [0x01u8; 16];
        let salt_b = [0x02u8; 16];

        let enc_a = derive_enc_key(&raw_key, &salt_a, &MACOS_4_1_7_31);
        let enc_b = derive_enc_key(&raw_key, &salt_b, &MACOS_4_1_7_31);
        assert_ne!(enc_a, enc_b);
    }

    #[test]
    fn test_mac_salt_xor() {
        let salt = [0x00u8; 16];
        let mac_salt: [u8; 16] = std::array::from_fn(|i| salt[i] ^ 0x3a);
        assert!(mac_salt.iter().all(|&b| b == 0x3a));
    }
}
