use crate::error::MediaError;
use crate::types::TranscodeAudioResult;

/// Strip the WeChat `\x02` prefix from SILK data if present.
/// WeChat prepends a `\x02` byte before the standard `#!SILK_V3` header.
#[cfg(feature = "audio")]
fn strip_wechat_silk_prefix(data: &[u8]) -> &[u8] {
    if data.first() == Some(&0x02) {
        &data[1..]
    } else {
        data
    }
}

#[cfg(feature = "audio")]
fn decode_silk_to_pcm(data: &[u8]) -> Result<Vec<u8>, MediaError> {
    let silk_data = strip_wechat_silk_prefix(data);
    silk_rs::decode_silk(silk_data, 24000).map_err(|e| MediaError::SilkDecodeFailed {
        reason: e.to_string(),
    })
}

#[cfg(feature = "audio")]
pub fn transcode_silk_to_ogg_opus(data: &[u8]) -> Result<TranscodeAudioResult, MediaError> {
    if !crate::ffmpeg::ffmpeg_available() {
        return Err(MediaError::FfmpegNotFound);
    }

    let pcm = decode_silk_to_pcm(data)?;
    let ogg = crate::ffmpeg::run_ffmpeg(
        &pcm,
        &[
            "-hide_banner",
            "-loglevel",
            "error",
            "-f",
            "s16le",
            "-ar",
            "24000",
            "-ac",
            "1",
            "-i",
            "pipe:0",
            "-c:a",
            "libopus",
            "-b:a",
            "32k",
            "-f",
            "ogg",
            "pipe:1",
        ],
    )?;

    Ok(TranscodeAudioResult {
        data: ogg,
        ext: "ogg",
        mime: "audio/ogg",
        transcoded: true,
    })
}

/// Transcode SILK audio to MP3.
///
/// Requires the `audio` cargo feature (for SILK decoding) and ffmpeg (for MP3 encoding).
///
/// Returns:
/// - `AudioFeatureDisabled` error if the `audio` feature is not enabled.
/// - `TranscodeAudioResult { transcoded: false, ext: "silk" }` if ffmpeg is not available
///   (returns original SILK data unchanged).
/// - `TranscodeAudioResult { transcoded: true, ext: "mp3" }` on full success.
#[cfg(feature = "audio")]
pub fn transcode_silk_to_mp3(data: &[u8]) -> Result<TranscodeAudioResult, MediaError> {
    if !crate::ffmpeg::ffmpeg_available() {
        // ffmpeg not available → return original SILK data unchanged
        return Ok(TranscodeAudioResult {
            data: data.to_vec(),
            ext: "silk",
            mime: "audio/x-silk",
            transcoded: false,
        });
    }

    let pcm = decode_silk_to_pcm(data)?;

    // PCM → MP3 via ffmpeg
    let mp3 = crate::ffmpeg::run_ffmpeg(
        &pcm,
        &[
            "-hide_banner",
            "-loglevel",
            "error",
            "-f",
            "s16le",
            "-ar",
            "24000",
            "-ac",
            "1",
            "-i",
            "pipe:0",
            "-b:a",
            "64k",
            "-f",
            "mp3",
            "pipe:1",
        ],
    )?;

    Ok(TranscodeAudioResult {
        data: mp3,
        ext: "mp3",
        mime: "audio/mpeg",
        transcoded: true,
    })
}

/// Stub when `audio` feature is not enabled.
#[cfg(not(feature = "audio"))]
pub fn transcode_silk_to_mp3(_data: &[u8]) -> Result<TranscodeAudioResult, MediaError> {
    Err(MediaError::AudioFeatureDisabled)
}

#[cfg(not(feature = "audio"))]
pub fn transcode_silk_to_ogg_opus(_data: &[u8]) -> Result<TranscodeAudioResult, MediaError> {
    Err(MediaError::AudioFeatureDisabled)
}
