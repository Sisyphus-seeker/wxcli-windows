use std::collections::HashSet;

pub const MAX_HEX_LEN: usize = 192;
pub const MAX_PATTERN_BYTES: usize = (MAX_HEX_LEN + 3) * 2;

/// A candidate key found by scanning a memory chunk for an SQL hex literal.
///
/// Supported payload forms (mirrors `refs/wx-decrypt/find_all_keys.py`):
/// - `x'<64 hex>'`   → enc_key only
/// - `x'<96 hex>'`   → enc_key + salt
/// - `x'<98..192 hex, even>'` → enc_key = first 64 hex, salt = last 32 hex
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct FoundKey {
    pub enc_key: [u8; 32],
    pub salt: Option<[u8; 16]>,
}

/// Scan `buf` for supported `x'<...>'` hex literal patterns.
pub fn scan_chunk(buf: &[u8]) -> Vec<FoundKey> {
    let mut seen = HashSet::new();
    let mut results = Vec::new();

    scan_encoded_patterns(buf, 1, &mut seen, &mut results);
    scan_encoded_patterns(buf, 2, &mut seen, &mut results);
    results
}

/// Scan for standalone 64-hex-character keys in ASCII and UTF-16LE text.
pub fn scan_bare_hex_keys(buf: &[u8]) -> Vec<[u8; 32]> {
    let mut seen = HashSet::new();
    let mut results = Vec::new();
    for stride in [1, 2] {
        scan_bare_encoded_keys(buf, stride, &mut seen, &mut results);
    }
    results
}

fn scan_bare_encoded_keys(
    buf: &[u8],
    stride: usize,
    seen: &mut HashSet<[u8; 32]>,
    results: &mut Vec<[u8; 32]>,
) {
    let encoded_byte = |index: usize| -> Option<u8> {
        let byte = *buf.get(index)?;
        if stride == 2 && *buf.get(index + 1)? != 0 {
            return None;
        }
        Some(byte)
    };

    let encoded_len = 64 * stride;
    if buf.len() < encoded_len {
        return;
    }

    for start in 0..=buf.len() - encoded_len {
        if !encoded_byte(start).is_some_and(|byte| byte.is_ascii_hexdigit()) {
            continue;
        }
        if start >= stride
            && encoded_byte(start - stride).is_some_and(|byte| byte.is_ascii_hexdigit())
        {
            continue;
        }

        let mut encoded = [0u8; 64];
        let mut valid = true;
        for (index, output) in encoded.iter_mut().enumerate() {
            match encoded_byte(start + index * stride) {
                Some(byte) if byte.is_ascii_hexdigit() => *output = byte,
                _ => {
                    valid = false;
                    break;
                }
            }
        }
        if !valid || encoded_byte(start + encoded_len).is_some_and(|byte| byte.is_ascii_hexdigit())
        {
            continue;
        }

        if let Ok(decoded) = hex::decode(encoded) {
            let mut key = [0u8; 32];
            key.copy_from_slice(&decoded);
            if seen.insert(key) {
                results.push(key);
            }
        }
    }
}

fn scan_encoded_patterns(
    buf: &[u8],
    stride: usize,
    seen: &mut HashSet<FoundKey>,
    results: &mut Vec<FoundKey>,
) {
    let encoded_byte = |index: usize| -> Option<u8> {
        let byte = *buf.get(index)?;
        if stride == 2 && *buf.get(index + 1)? != 0 {
            return None;
        }
        Some(byte)
    };

    if buf.len() < stride * 2 {
        return;
    }

    let mut i = 0;
    while i + stride < buf.len() {
        if !matches!(encoded_byte(i), Some(b'x' | b'X')) || encoded_byte(i + stride) != Some(b'\'')
        {
            i += 1;
            continue;
        }

        let payload_start = i + 2 * stride;
        let mut payload_end = payload_start;
        let mut hex_bytes = Vec::with_capacity(MAX_HEX_LEN);
        while hex_bytes.len() < MAX_HEX_LEN {
            let Some(byte) = encoded_byte(payload_end) else {
                break;
            };
            if !byte.is_ascii_hexdigit() {
                break;
            }
            hex_bytes.push(byte);
            payload_end += stride;
        }

        let Some(terminator) = encoded_byte(payload_end) else {
            break;
        };

        if terminator != b'\'' {
            i += 1;
            continue;
        }

        let hex_len = hex_bytes.len();
        if !is_supported_hex_len(hex_len) {
            i += 1;
            continue;
        }

        if let Some(found) = decode_found_key(&hex_bytes) {
            if seen.insert(found.clone()) {
                results.push(found);
            }
        }

        i = payload_end + stride;
    }
}

fn is_supported_hex_len(len: usize) -> bool {
    len == 64 || len == 96 || (len > 96 && len <= MAX_HEX_LEN && len.is_multiple_of(2))
}

fn decode_found_key(hex_slice: &[u8]) -> Option<FoundKey> {
    let enc_vec = hex::decode(&hex_slice[..64]).ok()?;
    let mut enc_key = [0u8; 32];
    enc_key.copy_from_slice(&enc_vec);

    let salt = match hex_slice.len() {
        64 => None,
        96 => decode_salt(&hex_slice[64..96]),
        len if len > 96 && len % 2 == 0 => decode_salt(&hex_slice[len - 32..len]),
        _ => None,
    };

    Some(FoundKey { enc_key, salt })
}

fn decode_salt(hex_slice: &[u8]) -> Option<[u8; 16]> {
    let salt_vec = hex::decode(hex_slice).ok()?;
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&salt_vec);
    Some(salt)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENC_HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const SALT_HEX: &str = "fedcba9876543210fedcba9876543210";

    fn expected_enc_key() -> [u8; 32] {
        let v = hex::decode(ENC_HEX).unwrap();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&v);
        arr
    }

    fn expected_salt() -> [u8; 16] {
        let v = hex::decode(SALT_HEX).unwrap();
        let mut arr = [0u8; 16];
        arr.copy_from_slice(&v);
        arr
    }

    #[test]
    fn exact_96_hex_returns_key_and_salt() {
        let buf = format!("x'{}{}'", ENC_HEX, SALT_HEX).into_bytes();
        let keys = scan_chunk(&buf);
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].enc_key, expected_enc_key());
        assert_eq!(keys[0].salt, Some(expected_salt()));
    }

    #[test]
    fn exact_64_hex_returns_key_only() {
        let buf = format!("x'{}'", ENC_HEX).into_bytes();
        let keys = scan_chunk(&buf);
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].enc_key, expected_enc_key());
        assert_eq!(keys[0].salt, None);
    }

    #[test]
    fn long_hex_uses_first_key_and_last_salt() {
        let middle = "a1".repeat(20);
        let buf = format!("x'{}{}{}'", ENC_HEX, middle, SALT_HEX).into_bytes();
        let keys = scan_chunk(&buf);
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].enc_key, expected_enc_key());
        assert_eq!(keys[0].salt, Some(expected_salt()));
    }

    #[test]
    fn invalid_mid_length_hex_is_ignored() {
        let payload = format!("{}{}", ENC_HEX, "ab".repeat(8)); // 80 hex
        let buf = format!("x'{}'", payload).into_bytes();
        let keys = scan_chunk(&buf);
        assert!(keys.is_empty());
    }

    #[test]
    fn mixed_case_hex_decoded_correctly() {
        let mixed_enc: String = ENC_HEX
            .chars()
            .enumerate()
            .map(|(i, c)| {
                if i % 2 == 0 {
                    c.to_ascii_uppercase()
                } else {
                    c
                }
            })
            .collect();
        let mixed_salt: String = SALT_HEX
            .chars()
            .enumerate()
            .map(|(i, c)| {
                if i % 2 == 0 {
                    c.to_ascii_uppercase()
                } else {
                    c
                }
            })
            .collect();
        let buf = format!("x'{}{}'", mixed_enc, mixed_salt).into_bytes();
        let keys = scan_chunk(&buf);
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].enc_key, expected_enc_key());
        assert_eq!(keys[0].salt, Some(expected_salt()));
    }

    #[test]
    fn uppercase_prefix_is_supported() {
        let buf = format!("X'{}{}'", ENC_HEX, SALT_HEX).into_bytes();
        let keys = scan_chunk(&buf);
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].enc_key, expected_enc_key());
        assert_eq!(keys[0].salt, Some(expected_salt()));
    }

    #[test]
    fn utf16le_pattern_is_supported() {
        let text = format!("x'{}{}'", ENC_HEX, SALT_HEX);
        let buf: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let keys = scan_chunk(&buf);
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].enc_key, expected_enc_key());
        assert_eq!(keys[0].salt, Some(expected_salt()));
    }

    #[test]
    fn duplicate_patterns_are_deduplicated() {
        let pattern = format!("x'{}{}'", ENC_HEX, SALT_HEX);
        let buf = format!("{}__{}", pattern, pattern).into_bytes();
        let keys = scan_chunk(&buf);
        assert_eq!(keys.len(), 1);
    }

    #[test]
    fn incomplete_pattern_at_end_is_ignored() {
        let buf = format!("x'{}", ENC_HEX).into_bytes();
        let keys = scan_chunk(&buf);
        assert!(keys.is_empty());
    }

    #[test]
    fn bare_ascii_key_is_found_with_boundaries() {
        let buf = format!("prefix:{ENC_HEX}:suffix").into_bytes();
        assert_eq!(scan_bare_hex_keys(&buf), vec![expected_enc_key()]);
    }

    #[test]
    fn bare_utf16le_key_is_found() {
        let text = format!(" {ENC_HEX} ");
        let buf: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
        assert_eq!(scan_bare_hex_keys(&buf), vec![expected_enc_key()]);
    }

    #[test]
    fn bare_key_inside_longer_hex_run_is_ignored() {
        let buf = format!("a{ENC_HEX}f").into_bytes();
        assert!(scan_bare_hex_keys(&buf).is_empty());
    }
}
