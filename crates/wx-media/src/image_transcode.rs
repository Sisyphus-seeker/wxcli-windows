use crate::error::MediaError;
use crate::ffmpeg::{ffmpeg_available, ffprobe_available, run_ffmpeg, run_ffprobe};
use crate::types::TranscodeImageResult;
use crate::wxgf::{parse_wxgf, WxgfContent};

/// Transcode a WXGF container to a standard image format.
///
/// - Embedded JPG/PNG: returned directly, `transcoded: true`.
/// - HEVC + ffmpeg available: single frame → PNG, multi frame → GIF, `transcoded: true`.
/// - HEVC + no ffmpeg: returns raw HEVC bytes, `transcoded: false`.
pub fn transcode_wxgf(data: &[u8]) -> Result<TranscodeImageResult, MediaError> {
    let content = parse_wxgf(data)?;

    match content {
        WxgfContent::EmbeddedImage { data, ext } => Ok(TranscodeImageResult {
            data,
            ext,
            transcoded: true,
        }),
        WxgfContent::Hevc(hevc) => {
            if !ffmpeg_available() {
                return Ok(TranscodeImageResult {
                    data: hevc,
                    ext: "hevc",
                    transcoded: false,
                });
            }

            let frame_count = count_hevc_frames(&hevc);

            if frame_count > 1 {
                // Multi-frame → GIF
                let gif = run_ffmpeg(
                    &hevc,
                    &[
                        "-hide_banner",
                        "-loglevel",
                        "error",
                        "-f",
                        "hevc",
                        "-i",
                        "pipe:0",
                        "-filter_complex",
                        "[0:v]split[s0][s1];[s0]palettegen[p];[s1][p]paletteuse",
                        "-loop",
                        "0",
                        "-f",
                        "gif",
                        "pipe:1",
                    ],
                )?;
                Ok(TranscodeImageResult {
                    data: gif,
                    ext: "gif",
                    transcoded: true,
                })
            } else {
                // Single frame → PNG
                let png = run_ffmpeg(
                    &hevc,
                    &[
                        "-hide_banner",
                        "-loglevel",
                        "error",
                        "-f",
                        "hevc",
                        "-i",
                        "pipe:0",
                        "-frames:v",
                        "1",
                        "-f",
                        "image2pipe",
                        "-vcodec",
                        "png",
                        "pipe:1",
                    ],
                )?;
                Ok(TranscodeImageResult {
                    data: png,
                    ext: "png",
                    transcoded: true,
                })
            }
        }
    }
}

/// Count frames in an HEVC bitstream using ffprobe.
/// Returns 1 as default if ffprobe is unavailable or parsing fails.
fn count_hevc_frames(hevc: &[u8]) -> usize {
    if !ffprobe_available() {
        return 1;
    }

    let result = run_ffprobe(
        hevc,
        &[
            "-v",
            "error",
            "-count_frames",
            "-select_streams",
            "v:0",
            "-show_entries",
            "stream=nb_read_frames",
            "-of",
            "default=nw=1:nk=1",
            "-f",
            "hevc",
            "-i",
            "pipe:0",
        ],
    );

    match result {
        Ok(s) => s.trim().parse::<usize>().unwrap_or(1),
        Err(_) => 1,
    }
}
