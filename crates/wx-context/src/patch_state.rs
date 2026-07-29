use std::path::{Path, PathBuf};

use crate::cache::format_system_time;

/// Returns the path for the WAL failed marker: `dst.with_extension("db.wal_failed")`.
pub(crate) fn wal_failed_marker_path(dst: &Path) -> PathBuf {
    dst.with_extension("db.wal_failed")
}

/// Checks whether a previous WAL patch attempt failed for the current `(db_mtime, wal_mtime)`.
///
/// Returns `true` if the marker exists and its composite key matches the current mtimes,
/// meaning the same failing patch should not be retried.
pub(crate) fn is_wal_patch_failed(src: &Path, wal: &Path, dst: &Path) -> bool {
    let marker = wal_failed_marker_path(dst);
    let recorded = match std::fs::read_to_string(&marker) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let current = match composite_key(src, wal) {
        Some(k) => k,
        None => return false,
    };
    recorded.trim() == current
}

/// Writes a WAL failed marker with the composite key `"db_mtime_nanos:wal_mtime_nanos"`.
pub(crate) fn write_wal_failed_marker(
    src: &Path,
    wal: &Path,
    dst: &Path,
) -> Result<(), std::io::Error> {
    let key = composite_key(src, wal)
        .ok_or_else(|| std::io::Error::other("cannot read source mtimes"))?;
    let marker = wal_failed_marker_path(dst);
    std::fs::write(&marker, key)
}

/// Removes the WAL failed marker. Ignores "not found" errors.
pub(crate) fn clear_wal_failed_marker(dst: &Path) {
    let marker = wal_failed_marker_path(dst);
    let _ = std::fs::remove_file(&marker);
}

/// Builds the composite key `"db_mtime_nanos:wal_mtime_nanos"`.
fn composite_key(src: &Path, wal: &Path) -> Option<String> {
    let db_mtime = src.metadata().ok()?.modified().ok()?;
    let wal_mtime = wal.metadata().ok()?.modified().ok()?;
    Some(format!(
        "{}:{}",
        format_system_time(db_mtime),
        format_system_time(wal_mtime),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tempfile::TempDir;

    #[test]
    fn marker_path_format() {
        let p = PathBuf::from("/cache/message_0.db");
        assert_eq!(
            wal_failed_marker_path(&p),
            PathBuf::from("/cache/message_0.db.wal_failed")
        );
    }

    #[test]
    fn write_then_detect_failed() {
        let tmp = TempDir::new().unwrap();
        let src = tmp.path().join("test.db");
        let wal = tmp.path().join("test.db-wal");
        let dst = tmp.path().join("out/test.db");
        std::fs::create_dir_all(tmp.path().join("out")).unwrap();

        std::fs::write(&src, b"db-data").unwrap();
        std::fs::write(&wal, b"wal-data").unwrap();
        std::fs::write(&dst, b"cached").unwrap();

        // Before writing marker, should return false
        assert!(!is_wal_patch_failed(&src, &wal, &dst));

        // Write marker
        write_wal_failed_marker(&src, &wal, &dst).unwrap();

        // Now should return true
        assert!(is_wal_patch_failed(&src, &wal, &dst));
    }

    #[test]
    fn mtime_change_allows_retry() {
        let tmp = TempDir::new().unwrap();
        let src = tmp.path().join("test.db");
        let wal = tmp.path().join("test.db-wal");
        let dst = tmp.path().join("out/test.db");
        std::fs::create_dir_all(tmp.path().join("out")).unwrap();

        std::fs::write(&src, b"db-data").unwrap();
        std::fs::write(&wal, b"wal-data").unwrap();
        std::fs::write(&dst, b"cached").unwrap();

        write_wal_failed_marker(&src, &wal, &dst).unwrap();
        assert!(is_wal_patch_failed(&src, &wal, &dst));

        // Modify WAL file to change its mtime
        let new_mtime = filetime::FileTime::from_system_time(
            std::time::SystemTime::now() + Duration::from_secs(2),
        );
        filetime::set_file_mtime(&wal, new_mtime).unwrap();

        // Composite key no longer matches → retry allowed
        assert!(!is_wal_patch_failed(&src, &wal, &dst));
    }

    #[test]
    fn db_mtime_change_allows_retry() {
        let tmp = TempDir::new().unwrap();
        let src = tmp.path().join("test.db");
        let wal = tmp.path().join("test.db-wal");
        let dst = tmp.path().join("out/test.db");
        std::fs::create_dir_all(tmp.path().join("out")).unwrap();

        std::fs::write(&src, b"db-data").unwrap();
        std::fs::write(&wal, b"wal-data").unwrap();
        std::fs::write(&dst, b"cached").unwrap();

        write_wal_failed_marker(&src, &wal, &dst).unwrap();
        assert!(is_wal_patch_failed(&src, &wal, &dst));

        // Modify DB file mtime
        let new_mtime = filetime::FileTime::from_system_time(
            std::time::SystemTime::now() + Duration::from_secs(2),
        );
        filetime::set_file_mtime(&src, new_mtime).unwrap();

        assert!(!is_wal_patch_failed(&src, &wal, &dst));
    }

    #[test]
    fn clear_marker_allows_retry() {
        let tmp = TempDir::new().unwrap();
        let src = tmp.path().join("test.db");
        let wal = tmp.path().join("test.db-wal");
        let dst = tmp.path().join("out/test.db");
        std::fs::create_dir_all(tmp.path().join("out")).unwrap();

        std::fs::write(&src, b"db-data").unwrap();
        std::fs::write(&wal, b"wal-data").unwrap();
        std::fs::write(&dst, b"cached").unwrap();

        write_wal_failed_marker(&src, &wal, &dst).unwrap();
        assert!(is_wal_patch_failed(&src, &wal, &dst));

        clear_wal_failed_marker(&dst);
        assert!(!is_wal_patch_failed(&src, &wal, &dst));
    }

    #[test]
    fn clear_nonexistent_marker_is_noop() {
        let tmp = TempDir::new().unwrap();
        let dst = tmp.path().join("out/test.db");
        // Should not panic
        clear_wal_failed_marker(&dst);
    }
}
