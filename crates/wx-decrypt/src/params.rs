/// Encryption parameters for a specific WeChat version.
pub struct CryptoParams {
    pub page_size: usize,
    pub kdf_iter: u32,
    pub hmac_size: usize,
    pub reserve: usize,
    pub key_size: usize,
    pub salt_size: usize,
    pub iv_size: usize,
}

/// macOS WeChat 4.1.7.31: Apple SEE with PBKDF2-HMAC-SHA512.
pub const MACOS_4_1_7_31: CryptoParams = CryptoParams {
    page_size: 4096,
    kdf_iter: 256_000,
    hmac_size: 64, // SHA-512 output
    reserve: 80,   // IV(16) + HMAC(64)
    key_size: 32,
    salt_size: 16,
    iv_size: 16,
};

/// Windows Weixin 4.1.x uses the same 4 KiB WCDB page layout.
/// Every captured key is still validated against the real database HMAC before use.
pub const WINDOWS_4_1_X: CryptoParams = CryptoParams {
    page_size: 4096,
    kdf_iter: 256_000,
    hmac_size: 64,
    reserve: 80,
    key_size: 32,
    salt_size: 16,
    iv_size: 16,
};

pub fn platform_default_params() -> &'static CryptoParams {
    #[cfg(windows)]
    {
        &WINDOWS_4_1_X
    }
    #[cfg(not(windows))]
    {
        &MACOS_4_1_7_31
    }
}
