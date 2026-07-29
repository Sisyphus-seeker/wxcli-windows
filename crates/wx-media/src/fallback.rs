use std::path::{Path, PathBuf};

/// Find a video file by MD5 hash, scanning `video_dir/{YYYY-MM}/{md5}.mp4`.
///
/// Strategy: try `month_hint` first (fast path), then scan all YYYY-MM subdirectories.
pub fn find_video_by_md5(video_dir: &Path, md5: &str, month_hint: &str) -> Option<PathBuf> {
    let target = format!("{md5}.mp4");

    // Fast path: check hint month first
    let hint_path = video_dir.join(month_hint).join(&target);
    if hint_path.is_file() {
        return Some(hint_path);
    }

    // Scan all YYYY-MM subdirectories (skip hint month, already tried)
    let entries = std::fs::read_dir(video_dir).ok()?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if !is_month_dir(&name_str) || name_str.as_ref() == month_hint {
            continue;
        }
        let candidate = entry.path().join(&target);
        if candidate.is_file() {
            return Some(candidate);
        }
    }

    None
}

/// Find a file by title in `file_dir/{month_hint}/{title}`.
///
/// Only checks the specified month (no broad scan to avoid same-name ambiguity).
/// Sanitizes `title` to prevent path traversal.
pub fn find_file_by_name(file_dir: &Path, title: &str, month_hint: &str) -> Option<PathBuf> {
    // Sanitize: extract just the filename component to prevent path traversal
    let safe_basename = Path::new(title).file_name()?;
    let candidate = file_dir.join(month_hint).join(safe_basename);
    if candidate.is_file() {
        Some(candidate)
    } else {
        None
    }
}

/// Check if a directory name matches the `YYYY-MM` pattern.
fn is_month_dir(name: &str) -> bool {
    if name.len() != 7 {
        return false;
    }
    let bytes = name.as_bytes();
    // YYYY must be digits
    if !bytes[..4].iter().all(|b| b.is_ascii_digit()) {
        return false;
    }
    // Separator must be '-'
    if bytes[4] != b'-' {
        return false;
    }
    // MM must be 01-12
    let month: u8 = match name[5..7].parse() {
        Ok(m) => m,
        Err(_) => return false,
    };
    (1..=12).contains(&month)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_month_dir_valid() {
        assert!(is_month_dir("2024-01"));
        assert!(is_month_dir("2024-12"));
        assert!(is_month_dir("1999-06"));
    }

    #[test]
    fn test_is_month_dir_invalid() {
        assert!(!is_month_dir("2024-00"));
        assert!(!is_month_dir("2024-13"));
        assert!(!is_month_dir("other"));
        assert!(!is_month_dir("24-01"));
        assert!(!is_month_dir("2024/01"));
        assert!(!is_month_dir(""));
    }
}
