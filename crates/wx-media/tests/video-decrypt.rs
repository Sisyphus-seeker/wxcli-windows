use wx_media::{decrypt_video, decrypt_video_with_keystream};

#[test]
fn test_zero_keystream_returns_input_unchanged() {
    let ciphertext = b"hello world, this is a test video file";
    let keystream = vec![0u8; ciphertext.len()];
    let result = decrypt_video_with_keystream(ciphertext, &keystream);
    assert_eq!(result.data, ciphertext);
    assert!(!result.is_valid_mp4);
}

#[test]
fn test_keystream_shorter_than_ciphertext() {
    let ciphertext = vec![0xAAu8; 100];
    let keystream = vec![0xBBu8; 30];
    let result = decrypt_video_with_keystream(&ciphertext, &keystream);
    assert_eq!(result.data.len(), 100);
    // First 30 bytes: 0xAA ^ 0xBB = 0x11
    for &b in &result.data[..30] {
        assert_eq!(b, 0x11);
    }
    // Remaining 70 bytes: unchanged 0xAA
    for &b in &result.data[30..] {
        assert_eq!(b, 0xAA);
    }
}

#[test]
fn test_ftyp_detection_valid() {
    // Construct mock data that contains "ftyp" at offset 4 (standard MP4)
    let mut plaintext = vec![0u8; 64];
    plaintext[4..8].copy_from_slice(b"ftyp");
    let result = decrypt_video_with_keystream(&plaintext, &[0u8; 64]);
    assert!(result.is_valid_mp4);
}

#[test]
fn test_ftyp_detection_invalid() {
    let plaintext = vec![0u8; 64];
    let result = decrypt_video_with_keystream(&plaintext, &[0u8; 64]);
    assert!(!result.is_valid_mp4);
}

#[test]
fn test_ftyp_detected_after_xor() {
    // "ftyp" XORed with key at offset 4
    let key = vec![0x42u8; 32];
    let mut ciphertext = vec![0u8; 32];
    // Set bytes 4..8 so that after XOR with 0x42 they become "ftyp"
    ciphertext[4] = b'f' ^ 0x42;
    ciphertext[5] = b't' ^ 0x42;
    ciphertext[6] = b'y' ^ 0x42;
    ciphertext[7] = b'p' ^ 0x42;
    let result = decrypt_video_with_keystream(&ciphertext, &key);
    assert!(result.is_valid_mp4);
    assert_eq!(&result.data[4..8], b"ftyp");
}

#[test]
fn test_decrypt_video_with_seed() {
    // Just verify it runs without panic and produces output of correct length
    let ciphertext = vec![0u8; 256];
    let result = decrypt_video(&ciphertext, 42);
    assert_eq!(result.data.len(), 256);
}

#[test]
fn test_empty_ciphertext() {
    let result = decrypt_video(b"", 0);
    assert!(result.data.is_empty());
    assert!(!result.is_valid_mp4);
}
