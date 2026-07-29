use std::collections::HashMap;
use std::path::Path;

use crate::error::MediaError;
use crate::types::{DatDecryptOptions, DatFormat, DecodedImage, ImageType};

/// V1 signature: `07 08 V1 08 07`
const V1_MAGIC: &[u8; 6] = b"\x07\x08V1\x08\x07";
/// V2 signature: `07 08 V2 08 07`
const V2_MAGIC: &[u8; 6] = b"\x07\x08V2\x08\x07";
/// V1 fixed AES key: `cfcd208495d565ef` (md5("0")[:16])
const V1_FIXED_KEY: &[u8; 16] = b"cfcd208495d565ef";
/// Dat file header size: 6B signature + 4B aes_size + 4B xor_size + 1B padding = 15
const HEADER_SIZE: usize = 15;

/// Known image magic bytes for XOR key detection (ordered by header length, descending).
const IMAGE_MAGICS: &[(&[u8], ImageType)] = &[
    (&[0x77, 0x78, 0x67, 0x66], ImageType::Wxgf),
    (&[0x89, 0x50, 0x4E, 0x47], ImageType::Png),
    (&[0x47, 0x49, 0x46, 0x38], ImageType::Gif),
    (&[0x49, 0x49, 0x2A, 0x00], ImageType::Tif),
    (&[0x52, 0x49, 0x46, 0x46], ImageType::Webp), // RIFF header
    (&[0xFF, 0xD8, 0xFF], ImageType::Jpg),
];

/// Detect the dat encryption format from the first 6 bytes.
/// Returns `None` if it's an XOR-only file (no V1/V2 signature).
pub fn detect_dat_format(data: &[u8]) -> Option<DatFormat> {
    if data.len() < 6 {
        return None;
    }
    if &data[..6] == V1_MAGIC {
        Some(DatFormat::V1)
    } else if &data[..6] == V2_MAGIC {
        Some(DatFormat::V2)
    } else {
        None
    }
}

/// Detect image type from decrypted data header.
pub fn detect_image_type(data: &[u8]) -> ImageType {
    if data.len() >= 4 && data[..4] == [0x77, 0x78, 0x67, 0x66] {
        return ImageType::Wxgf;
    }
    // WEBP: RIFF....WEBP
    if data.len() >= 12 && data[..4] == [0x52, 0x49, 0x46, 0x46] && data[8..12] == *b"WEBP" {
        return ImageType::Webp;
    }
    for &(magic, img_type) in IMAGE_MAGICS {
        if img_type == ImageType::Webp {
            continue; // handled above with full check
        }
        if data.len() >= magic.len() && data[..magic.len()] == *magic {
            return img_type;
        }
    }
    // BMP: 2-byte magic 42 4D — only check if nothing else matched
    if data.len() >= 2 && data[..2] == [0x42, 0x4D] {
        return ImageType::Bmp;
    }
    ImageType::Unknown
}

/// Decrypt a `.dat` file (in-memory). Unified entry for XOR, V1, V2 formats.
pub fn decrypt_dat(data: &[u8], opts: &DatDecryptOptions) -> Result<DecodedImage, MediaError> {
    if data.len() < 3 {
        return Err(MediaError::InvalidFormat {
            reason: format!("data too short: {} bytes", data.len()),
        });
    }

    match detect_dat_format(data) {
        Some(DatFormat::V1) => decrypt_v1_v2(data, V1_FIXED_KEY, opts.xor_key, DatFormat::V1),
        Some(DatFormat::V2) => {
            let key = opts.v2_aes_key.as_ref().ok_or(MediaError::MissingV2Key)?;
            decrypt_v1_v2(data, key, opts.xor_key, DatFormat::V2)
        }
        None => decrypt_xor(data),
        _ => unreachable!(),
    }
}

/// XOR decryption: detect single-byte key via known image magic.
fn decrypt_xor(data: &[u8]) -> Result<DecodedImage, MediaError> {
    for &(magic, _) in IMAGE_MAGICS {
        if data.len() < magic.len() {
            continue;
        }
        let key = data[0] ^ magic[0];
        let matched = magic.iter().enumerate().all(|(i, &m)| data[i] ^ key == m);
        if matched {
            let decrypted: Vec<u8> = data.iter().map(|b| b ^ key).collect();
            let img_type = detect_image_type(&decrypted);
            return Ok(DecodedImage {
                data: decrypted,
                format: DatFormat::Xor,
                ext: img_type.ext().to_string(),
            });
        }
    }
    Err(MediaError::XorKeyDetectionFailed)
}

/// V1/V2 decryption: AES-128-ECB header + optional raw middle + optional XOR tail.
fn decrypt_v1_v2(
    data: &[u8],
    aes_key: &[u8; 16],
    xor_key: Option<u8>,
    format: DatFormat,
) -> Result<DecodedImage, MediaError> {
    if data.len() < HEADER_SIZE {
        return Err(MediaError::InvalidFormat {
            reason: format!(
                "V1/V2 header requires {} bytes, got {}",
                HEADER_SIZE,
                data.len()
            ),
        });
    }

    let aes_size = u32::from_le_bytes(data[6..10].try_into().unwrap()) as usize;
    let xor_size = u32::from_le_bytes(data[10..14].try_into().unwrap()) as usize;

    // AES alignment: round up to next multiple of 16 (+ 16 for PKCS7 padding block)
    let aligned_aes_size = (aes_size / 16 + 1) * 16;

    let payload = &data[HEADER_SIZE..];

    if aligned_aes_size > payload.len() {
        return Err(MediaError::InvalidFormat {
            reason: format!(
                "AES section ({} aligned) exceeds payload ({})",
                aligned_aes_size,
                payload.len()
            ),
        });
    }

    // Decrypt AES-ECB section
    let aes_ciphertext = &payload[..aligned_aes_size];
    let aes_plaintext = aes_ecb_decrypt(aes_ciphertext, aes_key)?;
    // Truncate to original aes_size (remove PKCS7 padding overshoot)
    let aes_out = if aes_plaintext.len() > aes_size {
        &aes_plaintext[..aes_size]
    } else {
        &aes_plaintext
    };

    // Raw middle section
    let raw_start = aligned_aes_size;
    let raw_end = payload.len().saturating_sub(xor_size);
    let raw_data = if raw_start < raw_end {
        &payload[raw_start..raw_end]
    } else {
        &[]
    };

    // XOR tail section
    let xor_data = &payload[payload.len().saturating_sub(xor_size)..];
    let xor_decrypted: Vec<u8> = if xor_size > 0 {
        let k = xor_key.unwrap_or(0x37); // default xor key
        xor_data.iter().map(|b| b ^ k).collect()
    } else {
        Vec::new()
    };

    let mut result = Vec::with_capacity(aes_out.len() + raw_data.len() + xor_decrypted.len());
    result.extend_from_slice(aes_out);
    result.extend_from_slice(raw_data);
    result.extend_from_slice(&xor_decrypted);

    let img_type = detect_image_type(&result);

    Ok(DecodedImage {
        data: result,
        format,
        ext: img_type.ext().to_string(),
    })
}

/// AES-128-ECB decrypt with PKCS7 unpadding.
fn aes_ecb_decrypt(ciphertext: &[u8], key: &[u8; 16]) -> Result<Vec<u8>, MediaError> {
    use aes::cipher::{BlockCipherDecrypt, KeyInit};
    use aes::Aes128;

    if ciphertext.is_empty() {
        return Ok(Vec::new());
    }
    if !ciphertext.len().is_multiple_of(16) {
        return Err(MediaError::AesDecryptFailed {
            reason: format!(
                "ciphertext length {} is not a multiple of 16",
                ciphertext.len()
            ),
        });
    }

    let cipher = Aes128::new(key.into());
    let mut decrypted = ciphertext.to_vec();

    for chunk in decrypted.chunks_exact_mut(16) {
        cipher.decrypt_block(chunk.try_into().expect("chunk length mismatch"));
    }

    // PKCS7 unpadding
    let padding = decrypted[decrypted.len() - 1] as usize;
    if padding == 0 || padding > 16 {
        return Err(MediaError::AesDecryptFailed {
            reason: format!(
                "invalid PKCS7 padding byte: {}",
                decrypted[decrypted.len() - 1]
            ),
        });
    }
    let valid = decrypted[decrypted.len() - padding..]
        .iter()
        .all(|&b| b as usize == padding);
    if !valid {
        return Err(MediaError::AesDecryptFailed {
            reason: "PKCS7 padding validation failed (wrong key?)".into(),
        });
    }
    decrypted.truncate(decrypted.len() - padding);

    Ok(decrypted)
}

/// Auto-detect the XOR key by scanning `_t.dat` thumbnail files in `attach_dir`.
///
/// JPEG files end with `FF D9`. In XOR-encrypted `.dat` files, the last 2 bytes
/// are `(0xFF ^ xor_key)` and `(0xD9 ^ xor_key)`. We derive the key from multiple
/// thumbnails and use majority voting for robustness.
///
/// Returns `None` if no thumbnails are found or votes are inconsistent.
pub fn detect_xor_key(attach_dir: &Path) -> Option<u8> {
    let mut votes: HashMap<u8, usize> = HashMap::new();

    for entry in walkdir_thumbnails(attach_dir) {
        let path = entry.path();
        let data = match std::fs::read(&path) {
            Ok(d) if d.len() >= 2 => d,
            _ => continue,
        };

        // For V1/V2 files, extract XOR key from the XOR tail section
        if data.len() >= HEADER_SIZE + 2 && (&data[..6] == V1_MAGIC || &data[..6] == V2_MAGIC) {
            let xor_size = u32::from_le_bytes(data[10..14].try_into().unwrap()) as usize;
            if xor_size >= 2 {
                // Last 2 bytes of file = last 2 bytes of XOR tail
                let tail_penultimate = data[data.len() - 2];
                let tail_last = data[data.len() - 1];
                let candidate = tail_penultimate ^ 0xFF;
                if tail_last ^ 0xD9 == candidate {
                    *votes.entry(candidate).or_insert(0) += 1;
                }
            }
            continue;
        }

        let tail_penultimate = data[data.len() - 2];
        let tail_last = data[data.len() - 1];

        // Derive XOR key from penultimate byte (should be 0xFF ^ key)
        let candidate = tail_penultimate ^ 0xFF;
        // Verify with last byte (should be 0xD9 ^ key)
        if tail_last ^ 0xD9 == candidate {
            *votes.entry(candidate).or_insert(0) += 1;
        }
    }

    // Return the most-voted key
    votes
        .into_iter()
        .max_by_key(|&(_, count)| count)
        .map(|(key, _)| key)
}

/// Walk directory recursively collecting `_t.dat` thumbnail files.
fn walkdir_thumbnails(dir: &Path) -> Vec<std::fs::DirEntry> {
    let mut results = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            if let Ok(ft) = entry.file_type() {
                if ft.is_dir() {
                    results.extend(walkdir_thumbnails(&entry.path()));
                } else if ft.is_file() {
                    let name = entry.file_name().to_string_lossy().to_string();
                    if name.ends_with("_t.dat") {
                        results.push(entry);
                    }
                }
            }
        }
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_detect_xor_key_from_thumbnails() {
        let dir = std::env::temp_dir().join("wechat_xor_test");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        // XOR key = 0xa5
        // JPEG ends with FF D9 → encrypted tail = (0xFF ^ 0xa5, 0xD9 ^ 0xa5) = (0x5a, 0x7c)
        let xor_key: u8 = 0xa5;
        let tail = [0xFF ^ xor_key, 0xD9 ^ xor_key];

        // Create 3 fake _t.dat thumbnails with consistent tail
        for i in 0..3 {
            let mut data = vec![0x00; 100];
            data.extend_from_slice(&tail);
            fs::write(dir.join(format!("img{i}_t.dat")), &data).unwrap();
        }

        let result = detect_xor_key(&dir);
        assert_eq!(result, Some(0xa5));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_detect_xor_key_empty_dir() {
        let dir = std::env::temp_dir().join("wechat_xor_test_empty");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        assert_eq!(detect_xor_key(&dir), None);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_detect_xor_key_from_v2_thumbnails() {
        let dir = std::env::temp_dir().join("wechat_xor_test_v2");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        // V2 thumbnail with xor_size=50, xor_key=0xa5
        let xor_key: u8 = 0xa5;
        let xor_size: u32 = 50;
        let mut data = Vec::new();
        data.extend_from_slice(V2_MAGIC); // 6 bytes
        data.extend_from_slice(&1024u32.to_le_bytes()); // aes_size
        data.extend_from_slice(&xor_size.to_le_bytes()); // xor_size
        data.push(0x00); // padding → 15 bytes header
                         // Payload: some AES data + raw middle + XOR tail
        data.extend_from_slice(&[0x00; 100]); // filler
                                              // XOR tail ends with JPEG EOI encrypted
        let tail_len = xor_size as usize;
        let filler_tail = vec![0x00; tail_len - 2];
        data.extend_from_slice(&filler_tail);
        data.push(0xFF ^ xor_key); // penultimate
        data.push(0xD9 ^ xor_key); // last

        fs::write(dir.join("img0_t.dat"), &data).unwrap();

        assert_eq!(detect_xor_key(&dir), Some(0xa5));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_detect_xor_key_v2_no_xor_section() {
        let dir = std::env::temp_dir().join("wechat_xor_test_v2_noxor");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        // V2 thumbnail with xor_size=0 (no XOR tail — cannot derive key)
        let mut data = Vec::new();
        data.extend_from_slice(V2_MAGIC);
        data.extend_from_slice(&1024u32.to_le_bytes()); // aes_size
        data.extend_from_slice(&0u32.to_le_bytes()); // xor_size = 0
        data.push(0x00);
        data.extend_from_slice(&[0x00; 100]);
        fs::write(dir.join("img0_t.dat"), &data).unwrap();

        assert_eq!(detect_xor_key(&dir), None);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_detect_xor_key_majority_voting() {
        let dir = std::env::temp_dir().join("wechat_xor_test_vote");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let xor_key: u8 = 0xa5;
        let good_tail = [0xFF ^ xor_key, 0xD9 ^ xor_key];

        // 3 files with key 0xa5
        for i in 0..3 {
            let mut data = vec![0x00; 50];
            data.extend_from_slice(&good_tail);
            fs::write(dir.join(format!("good{i}_t.dat")), &data).unwrap();
        }

        // 1 file with different key 0x37
        let other_key: u8 = 0x37;
        let bad_tail = [0xFF ^ other_key, 0xD9 ^ other_key];
        let mut data = vec![0x00; 50];
        data.extend_from_slice(&bad_tail);
        fs::write(dir.join("bad0_t.dat"), &data).unwrap();

        // Majority should win
        assert_eq!(detect_xor_key(&dir), Some(0xa5));

        let _ = fs::remove_dir_all(&dir);
    }
}
