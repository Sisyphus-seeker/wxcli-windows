use aes::cipher::{block_padding::NoPadding, BlockModeDecrypt, KeyIvInit};
use hmac::{Hmac, Mac};
use sha2::Sha512;

use crate::error::DecryptError;
use crate::params::CryptoParams;

type HmacSha512 = Hmac<Sha512>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// Verify HMAC for a page and decrypt it.
///
/// `page_num` is 0-indexed. The HMAC includes the 1-indexed page number as LE u32.
///
/// For page 0, the first `salt_size` bytes (salt) are skipped in both HMAC and
/// decryption — the caller is responsible for replacing them with the SQLite header.
pub fn decrypt_page(
    page_buf: &[u8],
    enc_key: &[u8; 32],
    mac_key: &[u8; 32],
    page_num: u32,
    params: &CryptoParams,
) -> Result<Vec<u8>, DecryptError> {
    let offset = if page_num == 0 { params.salt_size } else { 0 };

    // --- HMAC verification ---
    let hmac_data_end = params.page_size - params.reserve + params.iv_size;

    let mut mac = HmacSha512::new_from_slice(mac_key).expect("HMAC key length is always valid");
    mac.update(&page_buf[offset..hmac_data_end]);
    // Page number in HMAC is 1-indexed, little-endian u32.
    mac.update(&(page_num + 1).to_le_bytes());
    let calculated = mac.finalize().into_bytes();

    let stored_hmac = &page_buf[hmac_data_end..hmac_data_end + params.hmac_size];
    if calculated[..params.hmac_size] != *stored_hmac {
        return Err(DecryptError::HmacVerificationFailed { page_num });
    }

    // --- Extract IV from reserve area ---
    let iv_start = params.page_size - params.reserve;
    let iv = &page_buf[iv_start..iv_start + params.iv_size];

    // --- AES-256-CBC decrypt ---
    let encrypted = &page_buf[offset..params.page_size - params.reserve];
    let mut buf = encrypted.to_vec();

    Aes256CbcDec::new(enc_key.into(), iv.try_into().expect("IV length mismatch"))
        .decrypt_padded::<NoPadding>(&mut buf)
        .map_err(|e| DecryptError::AesDecryptFailed {
            page_num,
            reason: e.to_string(),
        })?;

    // Append the reserve area (IV + HMAC) unchanged.
    buf.extend_from_slice(&page_buf[params.page_size - params.reserve..params.page_size]);

    Ok(buf)
}

#[cfg(test)]
mod tests {
    use crate::params::MACOS_4_1_7_31;

    #[test]
    fn test_page_size_arithmetic() {
        let p = &MACOS_4_1_7_31;
        // For a non-zero page: decrypted data + reserve = page_size
        let data_len = p.page_size - p.reserve; // 4016
        let total = data_len + p.reserve; // 4096
        assert_eq!(total, p.page_size);
    }

    #[test]
    fn test_page0_size_arithmetic() {
        let p = &MACOS_4_1_7_31;
        // For page 0: (page_size - reserve - salt_size) + reserve = page_size - salt_size
        let data_len = p.page_size - p.reserve - p.salt_size; // 4000
        let total = data_len + p.reserve; // 4080
                                          // Caller prepends SQLite header (16 bytes) to reach 4096
        assert_eq!(total + p.salt_size, p.page_size);
    }
}
