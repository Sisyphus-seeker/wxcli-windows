use crate::error::MediaError;

/// Result of parsing a WXGF container.
#[derive(Debug)]
pub enum WxgfContent {
    /// Embedded standard image (JPG/PNG) found within the WXGF container.
    EmbeddedImage { data: Vec<u8>, ext: &'static str },
    /// HEVC bitstream extracted from the WXGF container (needs ffmpeg to transcode).
    Hevc(Vec<u8>),
}

const WXGF_MAGIC: &[u8; 4] = b"wxgf";
const HEVC_START_CODE_4: &[u8; 4] = &[0x00, 0x00, 0x00, 0x01];
const HEVC_START_CODE_3: &[u8; 3] = &[0x00, 0x00, 0x01];
const JPG_MAGIC: &[u8; 3] = &[0xFF, 0xD8, 0xFF];
const PNG_MAGIC: &[u8; 4] = &[0x89, 0x50, 0x4E, 0x47];

/// Scan the first `limit` bytes (after WXGF magic) for embedded JPG/PNG.
const EMBEDDED_SCAN_LIMIT: usize = 4096;

/// Parse a WXGF container, extracting the inner content.
///
/// Returns `EmbeddedImage` if a standard image (JPG/PNG) is found within the container,
/// or `Hevc` if an HEVC bitstream is found. Returns an error if the data is not a valid
/// WXGF container or contains no recognizable content.
pub fn parse_wxgf(data: &[u8]) -> Result<WxgfContent, MediaError> {
    if data.len() < 4 || &data[..4] != WXGF_MAGIC {
        return Err(MediaError::InvalidWxgf);
    }

    // Check for embedded JPG/PNG in the first 4KB
    let scan_end = data.len().min(EMBEDDED_SCAN_LIMIT);
    for i in 4..scan_end {
        if i + 3 <= data.len() && &data[i..i + 3] == JPG_MAGIC {
            return Ok(WxgfContent::EmbeddedImage {
                data: data[i..].to_vec(),
                ext: "jpg",
            });
        }
        if i + 4 <= data.len() && &data[i..i + 4] == PNG_MAGIC {
            return Ok(WxgfContent::EmbeddedImage {
                data: data[i..].to_vec(),
                ext: "png",
            });
        }
    }

    // Search for HEVC start code (4-byte first, then 3-byte fallback)
    if let Some(pos) = find_subsequence(data, HEVC_START_CODE_4) {
        return Ok(WxgfContent::Hevc(data[pos..].to_vec()));
    }
    if let Some(pos) = find_subsequence(data, HEVC_START_CODE_3) {
        return Ok(WxgfContent::Hevc(data[pos..].to_vec()));
    }

    Err(MediaError::InvalidWxgf)
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}
