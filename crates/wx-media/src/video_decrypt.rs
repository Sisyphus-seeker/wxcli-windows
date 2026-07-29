use crate::isaac64::Isaac64;
use crate::types::DecryptVideoResult;

const MAX_DECRYPT_LEN: usize = 131072; // 128 KB

/// Decrypt a WeChat Channels encrypted video using Isaac64 keystream XOR.
///
/// Only the first 128KB of the ciphertext is encrypted; the rest is plaintext.
/// Returns the decrypted data and whether it appears to be a valid MP4 (contains "ftyp").
pub fn decrypt_video(ciphertext: &[u8], seed: u64) -> DecryptVideoResult {
    let mut isaac = Isaac64::new(seed);
    let decrypt_len = ciphertext.len().min(MAX_DECRYPT_LEN);
    let keystream = isaac.keystream(decrypt_len);
    decrypt_video_with_keystream(ciphertext, &keystream)
}

/// Decrypt using a pre-generated keystream (useful for testing).
pub fn decrypt_video_with_keystream(ciphertext: &[u8], keystream: &[u8]) -> DecryptVideoResult {
    let decrypt_len = ciphertext.len().min(keystream.len());
    let mut data = Vec::with_capacity(ciphertext.len());

    // XOR the encrypted prefix
    for i in 0..decrypt_len {
        data.push(ciphertext[i] ^ keystream[i]);
    }

    // Append unencrypted tail
    if decrypt_len < ciphertext.len() {
        data.extend_from_slice(&ciphertext[decrypt_len..]);
    }

    // Check for MP4 signature in first 32 bytes
    let check_len = data.len().min(32);
    let is_valid_mp4 = data[..check_len].windows(4).any(|w| w == b"ftyp");

    DecryptVideoResult { data, is_valid_mp4 }
}
