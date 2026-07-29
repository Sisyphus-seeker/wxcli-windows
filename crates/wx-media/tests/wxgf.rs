use wx_media::{parse_wxgf, ImageType, MediaError, WxgfContent};

#[test]
fn test_non_wxgf_magic_returns_error() {
    let data = b"not wxgf data at all";
    let err = parse_wxgf(data).unwrap_err();
    assert!(matches!(err, MediaError::InvalidWxgf));
}

#[test]
fn test_too_short_returns_error() {
    let data = b"wxg"; // Only 3 bytes
    let err = parse_wxgf(data).unwrap_err();
    assert!(matches!(err, MediaError::InvalidWxgf));
}

#[test]
fn test_wxgf_with_hevc_4byte_start_code() {
    let mut data = b"wxgf".to_vec();
    // Some padding bytes before the HEVC start code
    data.extend_from_slice(&[0x00, 0x01, 0x02, 0x03]);
    // 4-byte HEVC start code
    data.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
    // Mock HEVC NALU data
    data.extend_from_slice(&[0x40, 0x01, 0xFF, 0xFF]);

    match parse_wxgf(&data).unwrap() {
        WxgfContent::Hevc(hevc_data) => {
            assert_eq!(&hevc_data[..4], &[0x00, 0x00, 0x00, 0x01]);
            assert_eq!(hevc_data.len(), 8); // start code + NALU data
        }
        WxgfContent::EmbeddedImage { .. } => panic!("expected Hevc"),
    }
}

#[test]
fn test_wxgf_with_hevc_3byte_start_code() {
    let mut data = b"wxgf".to_vec();
    data.extend_from_slice(&[0x01, 0x02, 0x03]);
    // 3-byte start code (no 4-byte found)
    data.extend_from_slice(&[0x00, 0x00, 0x01]);
    data.extend_from_slice(&[0x26, 0x01]);

    match parse_wxgf(&data).unwrap() {
        WxgfContent::Hevc(hevc_data) => {
            assert_eq!(&hevc_data[..3], &[0x00, 0x00, 0x01]);
        }
        WxgfContent::EmbeddedImage { .. } => panic!("expected Hevc"),
    }
}

#[test]
fn test_wxgf_with_embedded_jpg() {
    let mut data = b"wxgf".to_vec();
    // Some header bytes
    data.extend_from_slice(&[0x00; 10]);
    // JPG magic at offset 14
    data.extend_from_slice(&[0xFF, 0xD8, 0xFF, 0xE0]);
    // JPG data
    data.extend_from_slice(&[0x01, 0x02, 0x03]);

    match parse_wxgf(&data).unwrap() {
        WxgfContent::EmbeddedImage { data: img, ext } => {
            assert_eq!(ext, "jpg");
            assert_eq!(&img[..3], &[0xFF, 0xD8, 0xFF]);
        }
        WxgfContent::Hevc(_) => panic!("expected EmbeddedImage"),
    }
}

#[test]
fn test_wxgf_with_embedded_png() {
    let mut data = b"wxgf".to_vec();
    data.extend_from_slice(&[0x00; 10]);
    // PNG magic
    data.extend_from_slice(&[0x89, 0x50, 0x4E, 0x47]);
    data.extend_from_slice(&[0x0D, 0x0A, 0x1A, 0x0A]);

    match parse_wxgf(&data).unwrap() {
        WxgfContent::EmbeddedImage { data: img, ext } => {
            assert_eq!(ext, "png");
            assert_eq!(&img[..4], &[0x89, 0x50, 0x4E, 0x47]);
        }
        WxgfContent::Hevc(_) => panic!("expected EmbeddedImage"),
    }
}

#[test]
fn test_embedded_image_takes_priority_over_hevc() {
    let mut data = b"wxgf".to_vec();
    data.extend_from_slice(&[0x00; 10]);
    // JPG magic appears first
    data.extend_from_slice(&[0xFF, 0xD8, 0xFF, 0xE0]);
    data.extend_from_slice(&[0x00; 20]);
    // HEVC start code appears later
    data.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);

    match parse_wxgf(&data).unwrap() {
        WxgfContent::EmbeddedImage { ext, .. } => assert_eq!(ext, "jpg"),
        WxgfContent::Hevc(_) => panic!("embedded image should take priority"),
    }
}

#[test]
fn test_no_start_code_no_embedded_returns_error() {
    let mut data = b"wxgf".to_vec();
    data.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05]);
    let err = parse_wxgf(&data).unwrap_err();
    assert!(matches!(err, MediaError::InvalidWxgf));
}

#[test]
fn test_image_type_wxgf_ext() {
    assert_eq!(ImageType::Wxgf.ext(), "wxgf");
}
