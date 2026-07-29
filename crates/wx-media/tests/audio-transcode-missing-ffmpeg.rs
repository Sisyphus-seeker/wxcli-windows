#[cfg(feature = "audio")]
use wx_media::MediaError;

#[cfg(feature = "audio")]
fn silent_pcm_frame() -> Vec<u8> {
    vec![0_u8; 24_000 / 1_000 * 40 * 2]
}

#[cfg(feature = "audio")]
fn sample_silk() -> Vec<u8> {
    silk_rs::encode_silk(silent_pcm_frame(), 24_000, 24_000, true).unwrap()
}

#[cfg(feature = "audio")]
#[test]
fn audio_transcode_handles_missing_ffmpeg_with_explicit_results() {
    unsafe {
        std::env::set_var("FFMPEG_PATH", "/definitely-missing-ffmpeg");
    }
    wx_media::reset_ffmpeg_cache();

    let ogg = wx_media::transcode_silk_to_ogg_opus(&sample_silk());
    assert!(matches!(ogg, Err(MediaError::FfmpegNotFound)));

    let mp3 = wx_media::transcode_silk_to_mp3(&sample_silk()).unwrap();
    assert_eq!(mp3.ext, "silk");
    assert_eq!(mp3.mime, "audio/x-silk");
    assert!(!mp3.transcoded);
}
