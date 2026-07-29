use wx_media::Isaac64;

// Test vectors generated from correct BigInt-safe ISAAC-64 implementation.
// NOTE: The CipherTalk TS reference has a Number() precision bug in
// `mm[Number(x >> 3n) & 255]` that loses precision for 64-bit values > 2^53.
// Our Rust implementation matches the standard ISAAC-64 algorithm and the
// WeChat WASM module's correct 64-bit behavior.

#[test]
fn test_seed_0_next_u64() {
    let mut rng = Isaac64::new(0);
    assert_eq!(rng.next_u64(), 0x673f4a26e311355a);
    assert_eq!(rng.next_u64(), 0x80b58ce58cf970fd);
    assert_eq!(rng.next_u64(), 0xdfdbe39c37e83fb2);
    assert_eq!(rng.next_u64(), 0x7b81201809b6bbf7);
    assert_eq!(rng.next_u64(), 0x7fa9c030f3ff9cfc);
}

#[test]
fn test_seed_12345_next_u64() {
    let mut rng = Isaac64::new(12345);
    assert_eq!(rng.next_u64(), 0x22286913bb698089);
    assert_eq!(rng.next_u64(), 0x276beba6b7d70db1);
    assert_eq!(rng.next_u64(), 0x7c228f4bc32b9af1);
    assert_eq!(rng.next_u64(), 0x5f46814fb1b21e59);
    assert_eq!(rng.next_u64(), 0x977adb409ed5f786);
}

#[test]
fn test_keystream_16_bytes() {
    let mut rng = Isaac64::new(0);
    let ks = rng.keystream(16);
    assert_eq!(ks.len(), 16);
    assert_eq!(hex::encode(&ks), "673f4a26e311355a80b58ce58cf970fd");
}

#[test]
fn test_keystream_9_bytes_non_aligned() {
    let mut rng = Isaac64::new(0);
    let ks = rng.keystream(9);
    assert_eq!(ks.len(), 9);
    // First 8 bytes: BE of next_u64[0] = 0x673f4a26e311355a
    // Next 1 byte: first BE byte of next_u64[1] = 0x80
    assert_eq!(hex::encode(&ks), "673f4a26e311355a80");
}

#[test]
fn test_keystream_0_bytes() {
    let mut rng = Isaac64::new(0);
    let ks = rng.keystream(0);
    assert!(ks.is_empty());
}

#[test]
fn test_keystream_1_byte() {
    let mut rng = Isaac64::new(0);
    let ks = rng.keystream(1);
    assert_eq!(ks.len(), 1);
    // First BE byte of 0x673f4a26e311355a = 0x67
    assert_eq!(ks[0], 0x67);
}

#[test]
fn test_generate_exhausts_and_refills() {
    let mut rng = Isaac64::new(0);
    for _ in 0..256 {
        rng.next_u64();
    }
    // The 257th call triggers generate() and still works
    let val = rng.next_u64();
    assert_ne!(val, 0);
}
