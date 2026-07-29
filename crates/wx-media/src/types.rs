/// Detected `.dat` file encryption format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatFormat {
    /// Single-byte XOR encryption (legacy).
    Xor,
    /// V1: AES-128-ECB with fixed key `cfcd208495d565ef`.
    V1,
    /// V2: AES-128-ECB with per-account key + XOR tail.
    V2,
}

/// Options for decrypting a `.dat` file.
#[derive(Debug, Clone, Default)]
pub struct DatDecryptOptions {
    /// AES key for V2 format (16 bytes, ASCII alphanumeric).
    /// Required for V2, ignored for XOR/V1.
    pub v2_aes_key: Option<[u8; 16]>,
    /// XOR key for V2 tail section. If `None`, uses auto-detected or default.
    pub xor_key: Option<u8>,
}

/// Result of decrypting a `.dat` file.
#[derive(Debug)]
pub struct DecodedImage {
    /// Decrypted image bytes.
    pub data: Vec<u8>,
    /// Detected encryption format.
    pub format: DatFormat,
    /// Detected image file extension (jpg, png, gif, bmp, webp, tif, wxgf, bin).
    pub ext: String,
}

/// Detected image type from magic bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageType {
    Jpg,
    Png,
    Gif,
    Bmp,
    Webp,
    Tif,
    Wxgf,
    Unknown,
}

impl ImageType {
    pub fn ext(&self) -> &'static str {
        match self {
            Self::Jpg => "jpg",
            Self::Png => "png",
            Self::Gif => "gif",
            Self::Bmp => "bmp",
            Self::Webp => "webp",
            Self::Tif => "tif",
            Self::Wxgf => "wxgf",
            Self::Unknown => "bin",
        }
    }
}

/// Result of resolving a media file path from message metadata.
#[derive(Debug, Clone)]
pub struct MediaLookupResult {
    /// The md5 extracted from packed_info.
    pub file_md5: String,
    /// All candidate `.dat` file paths found.
    pub candidates: Vec<std::path::PathBuf>,
    /// Recommended file (original > `_h` > `_t`).
    pub recommended: Option<std::path::PathBuf>,
}

/// Hardlink query result for image/video/file.
#[derive(Debug, Clone, serde::Serialize)]
pub struct HardlinkEntry {
    /// Media type: "image", "video", "file".
    pub media_type: String,
    /// MD5 key.
    pub md5: String,
    /// File name.
    pub file_name: String,
    /// File size in bytes.
    pub file_size: i64,
    /// Last modification time (unix seconds).
    pub modify_time: i64,
    /// First directory segment.
    pub dir1: String,
    /// Second directory segment.
    pub dir2: String,
}

/// Result of decrypting a WeChat Channels video.
#[derive(Debug)]
pub struct DecryptVideoResult {
    /// Decrypted video bytes.
    pub data: Vec<u8>,
    /// Whether the decrypted data contains an MP4 "ftyp" signature in the first 32 bytes.
    pub is_valid_mp4: bool,
}

/// Result of transcoding a WXGF image.
#[derive(Debug)]
pub struct TranscodeImageResult {
    /// Output image bytes.
    pub data: Vec<u8>,
    /// File extension: "png", "gif", "jpg", or "hevc" (fallback).
    pub ext: &'static str,
    /// `true` if data is in a standard viewable format; `false` if raw HEVC (ffmpeg missing).
    pub transcoded: bool,
}

/// Result of transcoding SILK audio.
#[derive(Debug)]
pub struct TranscodeAudioResult {
    /// Output audio bytes.
    pub data: Vec<u8>,
    /// File extension: "ogg", "mp3", or "silk" (fallback when ffmpeg absent).
    pub ext: &'static str,
    /// Response MIME type for the output payload.
    pub mime: &'static str,
    /// `true` if output was transcoded; `false` if original SILK was returned unchanged.
    pub transcoded: bool,
}

/// Extracted voice blob from `media_N.db`.
#[derive(Debug)]
pub struct VoiceBlob {
    /// Server ID used to locate this voice.
    pub svr_id: String,
    /// Optional `VoiceInfo.chat_name_id` captured from indexed schemas.
    pub chat_name_id: Option<i64>,
    /// Raw SILK audio bytes.
    pub data: Vec<u8>,
}
