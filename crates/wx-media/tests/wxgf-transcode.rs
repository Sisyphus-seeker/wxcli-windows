use std::process::Command;
use std::sync::Mutex;

static FFMPEG_ENV_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn transcode_wxgf_respects_embedded_png_and_missing_ffmpeg_hevc_fallback() {
    let _guard = FFMPEG_ENV_LOCK.lock().unwrap();
    unsafe {
        std::env::set_var("FFMPEG_PATH", "/definitely-missing-ffmpeg");
    }
    wx_media::reset_ffmpeg_cache();

    let mut embedded_png = b"wxgfmetadata".to_vec();
    embedded_png.extend_from_slice(&sample_png());
    let embedded = wx_media::transcode_wxgf(&embedded_png).unwrap();
    assert_eq!(embedded.ext, "png");
    assert!(embedded.transcoded);
    assert_eq!(&embedded.data[..8], b"\x89PNG\r\n\x1a\n");

    let mut hevc = b"wxgfmetadata".to_vec();
    hevc.extend_from_slice(&[0x00, 0x00, 0x00, 0x01, 0x26, 0x01, 0x02, 0x03, 0x04]);
    let hevc_result = wx_media::transcode_wxgf(&hevc).unwrap();
    assert_eq!(hevc_result.ext, "hevc");
    assert!(!hevc_result.transcoded);
    assert_eq!(
        hevc_result.data,
        vec![0x00, 0x00, 0x00, 0x01, 0x26, 0x01, 0x02, 0x03, 0x04]
    );

    unsafe {
        std::env::remove_var("FFMPEG_PATH");
    }
}

#[test]
fn transcode_wxgf_hevc_returns_png_when_ffmpeg_is_available() {
    let _guard = FFMPEG_ENV_LOCK.lock().unwrap();
    unsafe {
        std::env::remove_var("FFMPEG_PATH");
    }
    wx_media::reset_ffmpeg_cache();

    if !wx_media::ffmpeg_available() {
        return;
    }

    let mut wxgf = b"wxgfmetadata".to_vec();
    wxgf.extend_from_slice(&sample_valid_hevc());

    let result = wx_media::transcode_wxgf(&wxgf).unwrap();
    assert_eq!(result.ext, "png");
    assert!(result.transcoded);
    assert_eq!(&result.data[..8], b"\x89PNG\r\n\x1a\n");
}

fn sample_png() -> Vec<u8> {
    vec![
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44,
        0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1F,
        0x15, 0xC4, 0x89, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9C, 0x63, 0xF8,
        0xCF, 0xC0, 0xF0, 0x1F, 0x00, 0x05, 0x00, 0x01, 0xFF, 0x89, 0x99, 0x3D, 0x1D, 0x00, 0x00,
        0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82,
    ]
}

fn sample_valid_hevc() -> Vec<u8> {
    let temp = tempfile::TempDir::new().unwrap();
    let output = temp.path().join("frame.hevc");
    let ffmpeg = std::env::var("FFMPEG_PATH").unwrap_or_else(|_| "ffmpeg".to_string());
    let status = Command::new(ffmpeg)
        .args([
            "-hide_banner",
            "-loglevel",
            "error",
            "-f",
            "lavfi",
            "-i",
            "color=c=red:s=64x64:d=0.04:r=1",
            "-frames:v",
            "1",
            "-c:v",
            "libx265",
            "-x265-params",
            "log-level=error",
            "-f",
            "hevc",
            output.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success());
    std::fs::read(output).unwrap()
}
