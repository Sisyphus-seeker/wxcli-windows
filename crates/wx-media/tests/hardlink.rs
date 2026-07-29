use std::path::Path;
use tempfile::TempDir;
use wx_media::{self, MediaError};

/// Create a hardlink.db with v3-style tables.
fn create_hardlink_db_v3(path: &Path, entries: &[(&str, &str, &str, i64, i64, i64, i64)]) {
    // entries: (table_prefix, md5, file_name, file_size, modify_time, dir1_rowid, dir2_rowid)
    let conn = rusqlite::Connection::open(path).unwrap();
    conn.execute_batch(
        "CREATE TABLE dir2id (rowid INTEGER PRIMARY KEY, username TEXT);
         CREATE TABLE image_hardlink_info_v3 (
             md5 TEXT, file_name TEXT, file_size INTEGER, modify_time INTEGER,
             dir1 INTEGER, dir2 INTEGER
         );
         CREATE TABLE video_hardlink_info_v3 (
             md5 TEXT, file_name TEXT, file_size INTEGER, modify_time INTEGER,
             dir1 INTEGER, dir2 INTEGER
         );
         CREATE TABLE file_hardlink_info_v3 (
             md5 TEXT, file_name TEXT, file_size INTEGER, modify_time INTEGER,
             dir1 INTEGER, dir2 INTEGER
         );",
    )
    .unwrap();

    // Insert dir2id entries
    conn.execute(
        "INSERT INTO dir2id (rowid, username) VALUES (1, 'wxid_alice')",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO dir2id (rowid, username) VALUES (2, '2026-03')",
        [],
    )
    .unwrap();

    for &(table_prefix, md5, file_name, file_size, modify_time, dir1, dir2) in entries {
        let table = format!("{}_hardlink_info_v3", table_prefix);
        conn.execute(
            &format!(
                "INSERT INTO {} (md5, file_name, file_size, modify_time, dir1, dir2) VALUES (?, ?, ?, ?, ?, ?)",
                table
            ),
            rusqlite::params![md5, file_name, file_size, modify_time, dir1, dir2],
        )
        .unwrap();
    }
}

/// Create a hardlink.db with only v4-style tables.
fn create_hardlink_db_v4(path: &Path) {
    let conn = rusqlite::Connection::open(path).unwrap();
    conn.execute_batch(
        "CREATE TABLE dir2id (rowid INTEGER PRIMARY KEY, username TEXT);
         CREATE TABLE image_hardlink_info_v4 (
             md5 TEXT, file_name TEXT, file_size INTEGER, modify_time INTEGER,
             dir1 INTEGER, dir2 INTEGER
         );
         CREATE TABLE video_hardlink_info_v4 (
             md5 TEXT, file_name TEXT, file_size INTEGER, modify_time INTEGER,
             dir1 INTEGER, dir2 INTEGER
         );
         CREATE TABLE file_hardlink_info_v4 (
             md5 TEXT, file_name TEXT, file_size INTEGER, modify_time INTEGER,
             dir1 INTEGER, dir2 INTEGER
         );",
    )
    .unwrap();

    conn.execute(
        "INSERT INTO dir2id (rowid, username) VALUES (1, 'wxid_bob')",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO dir2id (rowid, username) VALUES (2, '2026-01')",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO image_hardlink_info_v4 (md5, file_name, file_size, modify_time, dir1, dir2) \
         VALUES ('abc123', 'abc123_h.dat', 4096, 1709000000, 1, 2)",
        [],
    )
    .unwrap();
}

// ── Tests ────────────────────────────────────────────────────────────

#[test]
fn query_image_v3_by_md5() {
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("hardlink.db");
    create_hardlink_db_v3(
        &db_path,
        &[
            ("image", "aabbcc", "aabbcc_t.dat", 1024, 1709000000, 1, 2),
            ("image", "aabbcc", "aabbcc_h.dat", 8192, 1709000001, 1, 2),
        ],
    );

    let results = wx_media::query_hardlink(&db_path, "image", "aabbcc").unwrap();
    assert_eq!(results.len(), 2);
    // Should prefer _h.dat (high quality) — returned first
    assert_eq!(results[0].file_name, "aabbcc_h.dat");
    assert_eq!(results[0].dir1, "wxid_alice");
    assert_eq!(results[0].dir2, "2026-03");
}

#[test]
fn query_video_v3() {
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("hardlink.db");
    create_hardlink_db_v3(
        &db_path,
        &[("video", "vid001", "vid001.mp4", 102400, 1709000000, 1, 2)],
    );

    let results = wx_media::query_hardlink(&db_path, "video", "vid001").unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].media_type, "video");
    assert_eq!(results[0].file_size, 102400);
}

#[test]
fn query_file_by_name_prefix() {
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("hardlink.db");
    create_hardlink_db_v3(
        &db_path,
        &[(
            "file",
            "doc999",
            "doc999_report.pdf",
            51200,
            1709000000,
            1,
            2,
        )],
    );

    let results = wx_media::query_hardlink(&db_path, "file", "doc999").unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].file_name, "doc999_report.pdf");
}

#[test]
fn query_v4_fallback() {
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("hardlink.db");
    create_hardlink_db_v4(&db_path);

    let results = wx_media::query_hardlink(&db_path, "image", "abc123").unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].dir1, "wxid_bob");
}

#[test]
fn query_not_found() {
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("hardlink.db");
    create_hardlink_db_v3(&db_path, &[]);

    let result = wx_media::query_hardlink(&db_path, "image", "nonexistent");
    assert!(matches!(result, Err(MediaError::LookupMiss(_))));
}

#[test]
fn query_image_prefers_h_dat() {
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("hardlink.db");
    create_hardlink_db_v3(
        &db_path,
        &[
            ("image", "xyz", "xyz_t.dat", 512, 1709000000, 1, 2),
            ("image", "xyz", "xyz_h.dat", 4096, 1709000001, 1, 2),
            ("image", "xyz", "xyz.dat", 2048, 1709000002, 1, 2),
        ],
    );

    let results = wx_media::query_hardlink(&db_path, "image", "xyz").unwrap();
    // _h.dat should be first
    assert_eq!(results[0].file_name, "xyz_h.dat");
}

#[test]
fn hardlink_query_with_conn_prefers_v3_and_h_image() {
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("hardlink.db");
    create_hardlink_db_v3(
        &db_path,
        &[
            ("image", "img001", "img001.dat", 2048, 1709000002, 1, 2),
            ("image", "img001", "img001_h.dat", 4096, 1709000001, 1, 2),
        ],
    );
    let conn = rusqlite::Connection::open(&db_path).unwrap();

    let results = wx_media::query_hardlink_with_conn(&conn, "image", "img001").unwrap();
    assert_eq!(results.len(), 2);
    assert_eq!(results[0].file_name, "img001_h.dat");
}

#[test]
fn hardlink_query_with_conn_matches_video_and_file_prefixes() {
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("hardlink.db");
    create_hardlink_db_v3(
        &db_path,
        &[
            ("video", "vid002", "vid002.mp4", 102400, 1709000000, 1, 2),
            (
                "file",
                "doc123",
                "doc123_notes.txt",
                51200,
                1709000100,
                1,
                2,
            ),
        ],
    );
    let conn = rusqlite::Connection::open(&db_path).unwrap();

    let video = wx_media::query_hardlink_with_conn(&conn, "video", "vid002").unwrap();
    assert_eq!(video[0].file_name, "vid002.mp4");

    let file = wx_media::query_hardlink_with_conn(&conn, "file", "doc123").unwrap();
    assert_eq!(file[0].file_name, "doc123_notes.txt");
}

#[test]
fn hardlink_query_with_conn_rejects_unsupported_media_type() {
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("hardlink.db");
    create_hardlink_db_v3(&db_path, &[]);
    let conn = rusqlite::Connection::open(&db_path).unwrap();

    let result = wx_media::query_hardlink_with_conn(&conn, "voice", "abc");
    assert!(matches!(result, Err(MediaError::InvalidFormat { .. })));
}
