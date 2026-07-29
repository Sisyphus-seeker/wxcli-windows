use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use rusqlite::{params, Connection};
use tempfile::TempDir;
use wx_db::test_ddl;
use wx_db::{MessageQuery, WechatDb};

// Msg_29a6db07e8bbdb53f5d54cc3c309f3f1  = md5("wxid_alice")
const ALICE_TABLE: &str = "Msg_29a6db07e8bbdb53f5d54cc3c309f3f1";

fn create_fixture() -> TempDir {
    let dir = TempDir::new().unwrap();
    let base = dir.path();

    let contact_dir = base.join("contact");
    fs::create_dir_all(&contact_dir).unwrap();
    let conn = Connection::open(contact_dir.join("contact.db")).unwrap();
    test_ddl::create_test_contact_table(&conn);

    let session_dir = base.join("session");
    fs::create_dir_all(&session_dir).unwrap();
    let conn = Connection::open(session_dir.join("session.db")).unwrap();
    test_ddl::create_test_session_table(&conn);

    let msg_dir = base.join("message");
    fs::create_dir_all(&msg_dir).unwrap();
    create_shard(&msg_dir.join("message_0.db"), 1_700_000_000);

    dir
}

fn create_shard(path: &Path, timestamp: i64) {
    let conn = Connection::open(path).unwrap();
    conn.execute_batch("CREATE TABLE Timestamp (timestamp INTEGER);")
        .unwrap();
    conn.execute("INSERT INTO Timestamp VALUES (?1)", params![timestamp])
        .unwrap();
    conn.execute_batch("CREATE TABLE Name2Id (rowid INTEGER PRIMARY KEY, user_name TEXT);")
        .unwrap();
    conn.execute_batch(&format!(
        "CREATE TABLE [{ALICE_TABLE}] (
            sort_seq INTEGER,
            server_id INTEGER,
            local_type INTEGER,
            real_sender_id INTEGER,
            create_time INTEGER,
            message_content BLOB,
            packed_info_data BLOB,
            status INTEGER
        );"
    ))
    .unwrap();
    conn.execute(
        &format!("INSERT INTO [{ALICE_TABLE}] VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"),
        params![
            100_i64,
            1001_i64,
            1_u32,
            0_i32,
            1_700_000_100_i64,
            b"hello",
            None::<Vec<u8>>,
            0
        ],
    )
    .unwrap();
}

// ---- Tests ----

#[test]
fn open_without_pool_has_no_pool() {
    let dir = create_fixture();
    let db = WechatDb::open(dir.path()).unwrap();
    assert!(db.pool().is_none());
}

#[test]
fn open_with_pool_has_pool() {
    let dir = create_fixture();
    let db = WechatDb::open_with_pool(dir.path(), |_conn| Ok(())).unwrap();
    assert!(db.pool().is_some());
}

#[test]
fn fts_init_callback_is_called() {
    let dir = create_fixture();
    let called = Arc::new(AtomicBool::new(false));
    let called_clone = Arc::clone(&called);

    // Create a fake FTS db so the pool tries to open it
    let fts_path = dir.path().join("message").join("message_fts.db");
    Connection::open(&fts_path).unwrap();

    let db = WechatDb::open_with_pool(dir.path(), move |_conn| {
        called_clone.store(true, Ordering::SeqCst);
        Ok(())
    })
    .unwrap();

    assert!(db.pool().is_some());
    assert!(called.load(Ordering::SeqCst), "fts_init should be called");
}

#[test]
fn pooled_query_returns_same_results_as_non_pooled() {
    let dir = create_fixture();

    let db_no_pool = WechatDb::open(dir.path()).unwrap();
    let db_with_pool = WechatDb::open_with_pool(dir.path(), |_conn| Ok(())).unwrap();

    let query = MessageQuery::for_talker("wxid_alice");
    let result_no_pool = db_no_pool.query_messages(&query).unwrap();
    let result_with_pool = db_with_pool.query_messages(&query).unwrap();

    assert_eq!(result_no_pool.items.len(), result_with_pool.items.len());
    assert_eq!(result_no_pool.items.len(), 1);
    assert_eq!(
        result_no_pool.items[0].server_id,
        result_with_pool.items[0].server_id
    );
}

#[test]
fn reopen_all_pooled_picks_up_changes() {
    let dir = create_fixture();
    let mut db = WechatDb::open_with_pool(dir.path(), |_conn| Ok(())).unwrap();

    // Insert a new message outside the pool
    let shard_path = dir.path().join("message").join("message_0.db");
    {
        let conn = Connection::open(&shard_path).unwrap();
        conn.execute(
            &format!("INSERT INTO [{ALICE_TABLE}] VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"),
            params![
                200_i64,
                1002_i64,
                1_u32,
                0_i32,
                1_700_000_200_i64,
                b"world",
                None::<Vec<u8>>,
                0
            ],
        )
        .unwrap();
    }

    // Before reopen: pool connections are stale (may or may not see new data depending on WAL)
    // After reopen: must see the new data
    db.reopen_all_pooled().unwrap();

    let query = MessageQuery::for_talker("wxid_alice");
    let result = db.query_messages(&query).unwrap();
    assert_eq!(result.items.len(), 2);
}

#[cfg(unix)]
#[test]
fn pooled_query_works_after_shard_file_removed() {
    let dir = create_fixture();
    let db = WechatDb::open_with_pool(dir.path(), |_conn| Ok(())).unwrap();

    let shard_path = dir.path().join("message").join("message_0.db");
    fs::remove_file(&shard_path).unwrap();

    let query = MessageQuery::for_talker("wxid_alice");
    let result = db.query_messages(&query).unwrap();
    assert_eq!(result.items.len(), 1);
    assert_eq!(result.items[0].server_id, 1001);
}

#[test]
fn reopen_fts_with_pool() {
    let dir = create_fixture();

    // Create a FTS db file so the pool opens it
    let fts_path = dir.path().join("message").join("message_fts.db");
    Connection::open(&fts_path).unwrap();

    let mut db = WechatDb::open_with_pool(dir.path(), |_conn| Ok(())).unwrap();
    assert!(db.pool().unwrap().fts_conn().is_some());

    // reopen_fts should succeed
    db.reopen_fts().unwrap();
    assert!(db.pool().unwrap().fts_conn().is_some());
}

#[test]
fn reopen_fts_without_pool_is_noop() {
    let dir = create_fixture();
    let mut db = WechatDb::open(dir.path()).unwrap();
    assert!(db.pool().is_none());

    // reopen_fts on a db without pool should be a no-op
    db.reopen_fts().unwrap();
    assert!(db.pool().is_none());
}
