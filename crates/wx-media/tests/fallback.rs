use std::fs;
use tempfile::TempDir;

// --- find_video_by_md5 tests ---

#[test]
fn test_video_found_in_hint_month() {
    let dir = TempDir::new().unwrap();
    let month_dir = dir.path().join("2024-03");
    fs::create_dir(&month_dir).unwrap();
    fs::write(month_dir.join("abc123.mp4"), b"video").unwrap();

    let result = wx_media::find_video_by_md5(dir.path(), "abc123", "2024-03");
    assert_eq!(result, Some(month_dir.join("abc123.mp4")));
}

#[test]
fn test_video_found_in_other_month() {
    let dir = TempDir::new().unwrap();
    let month_dir = dir.path().join("2024-05");
    fs::create_dir(&month_dir).unwrap();
    fs::write(month_dir.join("abc123.mp4"), b"video").unwrap();

    let result = wx_media::find_video_by_md5(dir.path(), "abc123", "2024-03");
    assert_eq!(result, Some(month_dir.join("abc123.mp4")));
}

#[test]
fn test_video_not_found() {
    let dir = TempDir::new().unwrap();
    let result = wx_media::find_video_by_md5(dir.path(), "abc123", "2024-03");
    assert_eq!(result, None);
}

#[test]
fn test_video_ignores_non_month_dirs() {
    let dir = TempDir::new().unwrap();
    let other_dir = dir.path().join("other");
    fs::create_dir(&other_dir).unwrap();
    fs::write(other_dir.join("abc123.mp4"), b"video").unwrap();

    let result = wx_media::find_video_by_md5(dir.path(), "abc123", "2024-03");
    assert_eq!(result, None);
}

// --- find_file_by_name tests ---

#[test]
fn test_file_found_in_month() {
    let dir = TempDir::new().unwrap();
    let month_dir = dir.path().join("2024-03");
    fs::create_dir(&month_dir).unwrap();
    fs::write(month_dir.join("report.pdf"), b"data").unwrap();

    let result = wx_media::find_file_by_name(dir.path(), "report.pdf", "2024-03");
    assert_eq!(result, Some(month_dir.join("report.pdf")));
}

#[test]
fn test_file_not_found_wrong_month() {
    let dir = TempDir::new().unwrap();
    let month_dir = dir.path().join("2024-05");
    fs::create_dir(&month_dir).unwrap();
    fs::write(month_dir.join("report.pdf"), b"data").unwrap();

    let result = wx_media::find_file_by_name(dir.path(), "report.pdf", "2024-03");
    assert_eq!(result, None);
}

#[test]
fn test_file_not_found_empty() {
    let dir = TempDir::new().unwrap();
    let result = wx_media::find_file_by_name(dir.path(), "report.pdf", "2024-03");
    assert_eq!(result, None);
}

// --- Edge case tests ---

#[test]
fn test_video_hint_month_preferred() {
    let dir = TempDir::new().unwrap();
    // Create same md5 file in two months
    let hint_dir = dir.path().join("2024-03");
    let other_dir = dir.path().join("2024-05");
    fs::create_dir(&hint_dir).unwrap();
    fs::create_dir(&other_dir).unwrap();
    fs::write(hint_dir.join("abc123.mp4"), b"video-hint").unwrap();
    fs::write(other_dir.join("abc123.mp4"), b"video-other").unwrap();

    let result = wx_media::find_video_by_md5(dir.path(), "abc123", "2024-03");
    assert_eq!(result, Some(hint_dir.join("abc123.mp4")));
}

#[test]
fn test_file_with_special_chars() {
    let dir = TempDir::new().unwrap();
    let month_dir = dir.path().join("2024-03");
    fs::create_dir(&month_dir).unwrap();

    // CJK characters and spaces in filename
    let name = "\u{4F1A}\u{8BAE}\u{8BB0}\u{5F55} 2024.pdf";
    fs::write(month_dir.join(name), b"data").unwrap();

    let result = wx_media::find_file_by_name(dir.path(), name, "2024-03");
    assert_eq!(result, Some(month_dir.join(name)));
}

#[test]
fn test_file_path_traversal_blocked() {
    let dir = TempDir::new().unwrap();
    let month_dir = dir.path().join("2024-03");
    fs::create_dir(&month_dir).unwrap();

    // Create a file that a naive path join would reach via traversal
    let escape_target = dir.path().join("passwd");
    fs::write(&escape_target, b"secret").unwrap();

    // Path traversal attempt: "../passwd" relative to file_dir/2024-03/ would reach file_dir/passwd
    let result = wx_media::find_file_by_name(dir.path(), "../passwd", "2024-03");
    assert_eq!(result, None, "path traversal should be blocked");

    // Also test deeper traversal
    let result = wx_media::find_file_by_name(dir.path(), "../../etc/passwd", "2024-03");
    assert_eq!(result, None, "deep path traversal should be blocked");
}

#[test]
fn test_video_skips_non_mp4() {
    let dir = TempDir::new().unwrap();
    let month_dir = dir.path().join("2024-03");
    fs::create_dir(&month_dir).unwrap();
    // Create .avi instead of .mp4
    fs::write(month_dir.join("abc123.avi"), b"video").unwrap();

    let result = wx_media::find_video_by_md5(dir.path(), "abc123", "2024-03");
    assert_eq!(result, None);
}
