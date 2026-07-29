use crate::error::MediaError;

/// Protobuf marker preceding the 32-byte MD5 hex string in `packed_info`.
const PROTOBUF_MARKER: &[u8] = b"\x12\x22\x0a\x20";

/// Extract the 32-char hex MD5 from a `packed_info` protobuf blob.
///
/// Strategy:
/// 1. Primary: locate protobuf marker `\x12\x22\x0a\x20`, read next 32 bytes as hex.
/// 2. Fallback: scan for 32 contiguous lowercase hex characters.
pub fn extract_md5_from_packed_info(blob: &[u8]) -> Option<String> {
    if blob.is_empty() {
        return None;
    }

    // Primary: protobuf marker
    if let Some(idx) = find_subsequence(blob, PROTOBUF_MARKER) {
        let start = idx + PROTOBUF_MARKER.len();
        if start + 32 <= blob.len() {
            if let Ok(s) = std::str::from_utf8(&blob[start..start + 32]) {
                if is_hex_string(s) {
                    return Some(s.to_string());
                }
            }
        }
    }

    // Fallback: scan for 32 contiguous hex chars
    let hex_chars: &[u8] = b"0123456789abcdef";
    let mut i = 0;
    while i + 32 <= blob.len() {
        if hex_chars.contains(&blob[i]) {
            let candidate = &blob[i..i + 32];
            if candidate.iter().all(|b| hex_chars.contains(b)) {
                if let Ok(s) = std::str::from_utf8(candidate) {
                    return Some(s.to_string());
                }
            }
            i += 32;
        } else {
            i += 1;
        }
    }

    None
}

/// Look up `packed_info` for a given `local_id` in `message_resource.db`.
pub fn get_packed_info(db_path: &std::path::Path, local_id: i64) -> Result<Vec<u8>, MediaError> {
    let conn =
        rusqlite::Connection::open_with_flags(db_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let mut stmt =
        conn.prepare("SELECT packed_info FROM MessageResourceInfo WHERE local_id = ?")?;
    let blob: Vec<u8> = stmt
        .query_row(rusqlite::params![local_id], |row| row.get(0))
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => {
                MediaError::NotFound(format!("local_id {} not in MessageResourceInfo", local_id))
            }
            other => MediaError::Sqlite(other),
        })?;
    Ok(blob)
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn is_hex_string(s: &str) -> bool {
    s.len() == 32
        && s.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}
