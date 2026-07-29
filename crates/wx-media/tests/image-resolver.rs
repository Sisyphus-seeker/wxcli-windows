use std::fs;
use std::path::Path;
use tempfile::TempDir;
use wx_media::MediaError;

/// Create a minimal `message_resource.db` with a `MessageResourceInfo` table.
fn create_message_resource_db(path: &Path, rows: &[(i64, &[u8])]) {
    let conn = rusqlite::Connection::open(path).unwrap();
    conn.execute_batch(
        "CREATE TABLE MessageResourceInfo (
            local_id INTEGER PRIMARY KEY,
            packed_info BLOB
        );",
    )
    .unwrap();
    let mut stmt = conn
        .prepare("INSERT INTO MessageResourceInfo (local_id, packed_info) VALUES (?, ?)")
        .unwrap();
    for &(local_id, blob) in rows {
        stmt.execute(rusqlite::params![local_id, blob]).unwrap();
    }
}

/// Build a packed_info blob containing a protobuf-style MD5 marker.
/// Format: prefix + `\x12\x22\x0a\x20` + 32-byte hex MD5
fn make_packed_info(md5_hex: &str) -> Vec<u8> {
    let mut blob = vec![0x0A, 0x10]; // some prefix bytes
    blob.extend_from_slice(b"\x12\x22\x0a\x20");
    blob.extend_from_slice(md5_hex.as_bytes());
    blob.extend_from_slice(&[0x18, 0x01]); // trailing protobuf
    blob
}

/// Create a fake attach directory structure with .dat files.
fn create_attach_dir(
    base: &Path,
    username_hash: &str,
    month: &str,
    file_md5: &str,
    suffixes: &[&str],
) {
    let img_dir = base
        .join("msg")
        .join("attach")
        .join(username_hash)
        .join(month)
        .join("Img");
    fs::create_dir_all(&img_dir).unwrap();
    for suffix in suffixes {
        let name = format!("{}{}.dat", file_md5, suffix);
        fs::write(img_dir.join(name), b"fake dat content").unwrap();
    }
}

// ── packed_info parsing tests ────────────────────────────────────────

#[test]
fn extract_md5_protobuf_marker() {
    let md5 = "d41d8cd98f00b204e9800998ecf8427e";
    let blob = make_packed_info(md5);
    let result = wx_media::extract_md5_from_packed_info(&blob).unwrap();
    assert_eq!(result, md5);
}

#[test]
fn extract_md5_fallback_hex_scan() {
    // No protobuf marker, but contains 32 contiguous hex chars
    let md5 = "abcdef0123456789abcdef0123456789";
    let mut blob = vec![0x00, 0x01, 0x02];
    blob.extend_from_slice(md5.as_bytes());
    blob.extend_from_slice(&[0xFF, 0xFE]);
    let result = wx_media::extract_md5_from_packed_info(&blob).unwrap();
    assert_eq!(result, md5);
}

#[test]
fn extract_md5_no_match() {
    let blob = vec![0x00; 10];
    let result = wx_media::extract_md5_from_packed_info(&blob);
    assert!(result.is_none());
}

#[test]
fn extract_md5_empty() {
    assert!(wx_media::extract_md5_from_packed_info(&[]).is_none());
}

// ── resolve_image_by_md5 tests ───────────────────────────────────────

#[test]
fn resolve_image_by_md5_success() {
    let tmp = TempDir::new().unwrap();
    let base = tmp.path();

    let username = "testuser";
    let username_hash = format!("{:x}", md5::compute(username.as_bytes()));
    let file_md5 = "d41d8cd98f00b204e9800998ecf8427e";

    // Create attach dir with dat files (reuse helper)
    create_attach_dir(base, &username_hash, "2026-03", file_md5, &["", "_t", "_h"]);

    let result =
        wx_media::resolve_image_by_md5(username, &base.join("msg").join("attach"), file_md5)
            .unwrap();

    assert_eq!(result.file_md5, file_md5);
    assert_eq!(result.candidates.len(), 3);
    let rec = result.recommended.unwrap();
    let name = rec.file_name().unwrap().to_str().unwrap();
    assert_eq!(name, format!("{}_h.dat", file_md5));
}

#[test]
fn resolve_image_by_md5_no_dat_files() {
    let tmp = TempDir::new().unwrap();
    let attach_dir = tmp.path().join("msg").join("attach");
    fs::create_dir_all(&attach_dir).unwrap();

    let result =
        wx_media::resolve_image_by_md5("user", &attach_dir, "deadbeef12345678deadbeef12345678");
    assert!(matches!(result, Err(MediaError::NoDatFiles { .. })));
}

// ── image resolver integration tests ─────────────────────────────────

#[test]
fn resolve_image_path_success() {
    let tmp = TempDir::new().unwrap();
    let base = tmp.path();

    let username = "testuser";
    let username_hash = format!("{:x}", md5::compute(username.as_bytes()));
    let file_md5 = "d41d8cd98f00b204e9800998ecf8427e";

    // Create message_resource.db
    let db_path = base.join("db_storage").join("message");
    fs::create_dir_all(&db_path).unwrap();
    let resource_db = db_path.join("message_resource.db");
    let packed_info = make_packed_info(file_md5);
    create_message_resource_db(&resource_db, &[(42, &packed_info)]);

    // Create attach dir with dat files
    create_attach_dir(base, &username_hash, "2026-03", file_md5, &["", "_t", "_h"]);

    let result = wx_media::resolve_image(
        &resource_db,
        42, // local_id
        username,
        &base.join("msg").join("attach"),
    )
    .unwrap();

    assert_eq!(result.file_md5, file_md5);
    assert_eq!(result.candidates.len(), 3);
    // Recommended should prefer _h over the plain md5.dat variant.
    let rec = result.recommended.unwrap();
    let name = rec.file_name().unwrap().to_str().unwrap();
    assert_eq!(name, format!("{}_h.dat", file_md5));
}

#[test]
fn resolve_image_local_id_not_found() {
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("message_resource.db");
    create_message_resource_db(&db_path, &[]);

    let result = wx_media::resolve_image(&db_path, 999, "user", tmp.path());
    assert!(matches!(result, Err(MediaError::NotFound(_))));
}

#[test]
fn resolve_image_no_dat_files() {
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("message_resource.db");
    let file_md5 = "d41d8cd98f00b204e9800998ecf8427e";
    let packed_info = make_packed_info(file_md5);
    create_message_resource_db(&db_path, &[(1, &packed_info)]);

    // Don't create any attach dirs
    let attach_dir = tmp.path().join("msg").join("attach");
    fs::create_dir_all(&attach_dir).unwrap();

    let result = wx_media::resolve_image(&db_path, 1, "user", &attach_dir);
    assert!(matches!(result, Err(MediaError::NoDatFiles { .. })));
}
