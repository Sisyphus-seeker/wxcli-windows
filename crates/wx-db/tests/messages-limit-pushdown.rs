use std::fs;
use std::path::Path;

use rusqlite::{params, Connection};
use tempfile::TempDir;
use wx_db::test_ddl;
use wx_db::{MessageQuery, SortOrder, WechatDb, MSG_TYPE_TEXT};

// Msg_29a6db07e8bbdb53f5d54cc3c309f3f1 = md5("wxid_alice")
const ALICE_TABLE: &str = "Msg_29a6db07e8bbdb53f5d54cc3c309f3f1";

/// Create a fixture with 10 text messages for wxid_alice spread across 2 shards,
/// plus 1 damaged row in shard 0. This tests cross-shard LIMIT pushdown behavior.
///
/// Shard 0 (ts=1700000000): sort_seq 10,30,50,70,90 (5 text) + sort_seq 45 (damaged)
/// Shard 1 (ts=1710000000): sort_seq 20,40,60,80,100 (5 text)
///
/// Global ASC order: 10,20,30,40,50,60,70,80,90,100
fn create_limit_pushdown_fixture() -> TempDir {
    let dir = TempDir::new().unwrap();
    let base = dir.path();

    // contact/contact.db
    let contact_dir = base.join("contact");
    fs::create_dir_all(&contact_dir).unwrap();
    create_minimal_contact_db(&contact_dir.join("contact.db"));

    // session/session.db
    let session_dir = base.join("session");
    fs::create_dir_all(&session_dir).unwrap();
    create_minimal_session_db(&session_dir.join("session.db"));

    let msg_dir = base.join("message");
    fs::create_dir_all(&msg_dir).unwrap();

    create_shard_0(&msg_dir.join("message_0.db"));
    create_shard_1(&msg_dir.join("message_1.db"));

    dir
}

fn create_minimal_contact_db(path: &Path) {
    let conn = Connection::open(path).unwrap();
    test_ddl::create_test_contact_table_minimal(&conn);
}

fn create_minimal_session_db(path: &Path) {
    let conn = Connection::open(path).unwrap();
    test_ddl::create_test_session_table(&conn);
}

fn create_msg_table(conn: &Connection, table: &str) {
    conn.execute_batch("CREATE TABLE Timestamp (timestamp INTEGER);")
        .unwrap();
    conn.execute_batch("CREATE TABLE Name2Id (rowid INTEGER PRIMARY KEY, user_name TEXT);")
        .unwrap();
    conn.execute(
        "INSERT INTO Name2Id VALUES (?1, ?2)",
        params![1, "wxid_alice"],
    )
    .unwrap();
    conn.execute_batch(&format!(
        "CREATE TABLE [{table}] (
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
}

fn insert_text_msg(
    conn: &Connection,
    table: &str,
    sort_seq: i64,
    server_id: i64,
    create_time: i64,
    text: &str,
) {
    conn.execute(
        &format!("INSERT INTO [{table}] VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"),
        params![
            sort_seq,
            server_id,
            1_u32, // MSG_TYPE_TEXT
            1_i32,
            create_time,
            text.as_bytes(),
            None::<Vec<u8>>,
            0_i32,
        ],
    )
    .unwrap();
}

fn insert_image_msg(
    conn: &Connection,
    table: &str,
    sort_seq: i64,
    server_id: i64,
    create_time: i64,
) {
    conn.execute(
        &format!("INSERT INTO [{table}] VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"),
        params![
            sort_seq,
            server_id,
            3_u32, // MSG_TYPE_IMAGE
            1_i32,
            create_time,
            b"" as &[u8],
            None::<Vec<u8>>,
            0_i32,
        ],
    )
    .unwrap();
}

/// Shard 0: sort_seq 10,30,50,70,90 (text) + 45 (damaged zstd)
fn create_shard_0(path: &Path) {
    let conn = Connection::open(path).unwrap();
    create_msg_table(&conn, ALICE_TABLE);
    conn.execute(
        "INSERT INTO Timestamp VALUES (?1)",
        params![1_700_000_000_i64],
    )
    .unwrap();

    insert_text_msg(&conn, ALICE_TABLE, 10, 1001, 1_700_000_010, "msg-10");
    insert_text_msg(&conn, ALICE_TABLE, 30, 1003, 1_700_000_030, "msg-30");
    insert_text_msg(&conn, ALICE_TABLE, 50, 1005, 1_700_000_050, "msg-50");
    insert_text_msg(&conn, ALICE_TABLE, 70, 1007, 1_700_000_070, "msg-70");
    insert_text_msg(&conn, ALICE_TABLE, 90, 1009, 1_700_000_090, "msg-90");

    // Damaged zstd row at sort_seq=45
    let damaged_zstd: Vec<u8> = vec![0x28, 0xB5, 0x2F, 0xFD, 0xFF, 0xFF, 0xFF];
    conn.execute(
        &format!(
            "INSERT INTO [{table}] VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            table = ALICE_TABLE
        ),
        params![
            45_i64,
            1045_i64,
            1_u32,
            1_i32,
            1_700_000_045,
            damaged_zstd,
            None::<Vec<u8>>,
            0_i32,
        ],
    )
    .unwrap();

    // An image message at sort_seq=55 for msg_type filter testing
    insert_image_msg(&conn, ALICE_TABLE, 55, 1055, 1_700_000_055);
}

/// Shard 1: sort_seq 20,40,60,80,100 (text)
fn create_shard_1(path: &Path) {
    let conn = Connection::open(path).unwrap();
    create_msg_table(&conn, ALICE_TABLE);
    conn.execute(
        "INSERT INTO Timestamp VALUES (?1)",
        params![1_710_000_000_i64],
    )
    .unwrap();

    insert_text_msg(&conn, ALICE_TABLE, 20, 1002, 1_710_000_020, "msg-20");
    insert_text_msg(&conn, ALICE_TABLE, 40, 1004, 1_710_000_040, "msg-40");
    insert_text_msg(&conn, ALICE_TABLE, 60, 1006, 1_710_000_060, "msg-60");
    insert_text_msg(&conn, ALICE_TABLE, 80, 1008, 1_710_000_080, "msg-80");
    insert_text_msg(&conn, ALICE_TABLE, 100, 1010, 1_710_000_100, "msg-100");
}

// ---- Tests ----

#[test]
fn limit_pushdown_desc_limit_3() {
    let dir = create_limit_pushdown_fixture();
    let db = WechatDb::open(dir.path()).unwrap();

    let result = db
        .query_messages(
            &MessageQuery::for_talker("wxid_alice")
                .order(SortOrder::Desc)
                .limit(3),
        )
        .unwrap();

    assert_eq!(result.items.len(), 3);
    let seqs: Vec<i64> = result.items.iter().map(|m| m.sort_seq).collect();
    assert_eq!(seqs, vec![100, 90, 80], "top-3 DESC by sort_seq");
}

#[test]
fn limit_pushdown_asc_limit_offset() {
    let dir = create_limit_pushdown_fixture();
    let db = WechatDb::open(dir.path()).unwrap();

    // ASC, offset=1, limit=2: skip first, take next 2
    // Global ASC order (text only, but image at 55 too): 10,20,30,40,50,55(img),60,70,80,90,100
    // offset=1 skips 10, take 2 → 20, 30
    let result = db
        .query_messages(
            &MessageQuery::for_talker("wxid_alice")
                .order(SortOrder::Asc)
                .limit(2)
                .offset(1),
        )
        .unwrap();

    assert_eq!(result.items.len(), 2);
    let seqs: Vec<i64> = result.items.iter().map(|m| m.sort_seq).collect();
    assert_eq!(seqs, vec![20, 30]);
}

#[test]
fn limit_pushdown_msg_type_filter() {
    let dir = create_limit_pushdown_fixture();
    let db = WechatDb::open(dir.path()).unwrap();

    // msg_type=1 (text), limit=2, ASC → should get sort_seq 10, 20 (text only, skipping image at 55)
    let result = db
        .query_messages(
            &MessageQuery::for_talker("wxid_alice")
                .msg_type(MSG_TYPE_TEXT)
                .order(SortOrder::Asc)
                .limit(2),
        )
        .unwrap();

    assert_eq!(result.items.len(), 2);
    assert!(result.items.iter().all(|m| m.msg_type == MSG_TYPE_TEXT));
    let seqs: Vec<i64> = result.items.iter().map(|m| m.sort_seq).collect();
    assert_eq!(seqs, vec![10, 20]);
}

#[test]
fn limit_pushdown_keyword_disables_pushdown() {
    let dir = create_limit_pushdown_fixture();
    let db = WechatDb::open(dir.path()).unwrap();

    // keyword search still works (falls back to full scan path)
    let result = db
        .query_messages(
            &MessageQuery::for_talker("wxid_alice")
                .keyword("msg-30")
                .limit(2),
        )
        .unwrap();

    assert_eq!(result.items.len(), 1);
    assert_eq!(result.items[0].sort_seq, 30);
}

#[test]
fn limit_pushdown_with_filtered_count_disables_pushdown() {
    let dir = create_limit_pushdown_fixture();
    let db = WechatDb::open(dir.path()).unwrap();

    let result = db
        .query_messages(
            &MessageQuery::for_talker("wxid_alice")
                .msg_type(MSG_TYPE_TEXT)
                .with_filtered_count(true)
                .limit(2),
        )
        .unwrap();

    // filtered_count should reflect all text messages, not just the page
    assert_eq!(result.items.len(), 2);
    assert_eq!(
        result.stats.filtered_count,
        Some(10),
        "10 text messages total"
    );
}

#[test]
fn limit_pushdown_cross_shard_merge_correctness() {
    let dir = create_limit_pushdown_fixture();
    let db = WechatDb::open(dir.path()).unwrap();

    // Get all messages ASC to verify interleaving is correct
    let result = db
        .query_messages(
            &MessageQuery::for_talker("wxid_alice")
                .order(SortOrder::Asc)
                .limit(100),
        )
        .unwrap();

    // 12 total rows (6 shard0 + 5 shard1 + 1 damaged), 11 valid, 1 skipped
    let seqs: Vec<i64> = result.items.iter().map(|m| m.sort_seq).collect();
    // Verify global sort order is correct across shards (including image at 55)
    let mut sorted = seqs.clone();
    sorted.sort();
    assert_eq!(seqs, sorted, "global sort order must be maintained");

    // Verify both shards contributed
    assert!(seqs.contains(&10), "shard 0 message present");
    assert!(seqs.contains(&20), "shard 1 message present");
}

#[test]
fn limit_pushdown_damaged_row_skipped() {
    let dir = create_limit_pushdown_fixture();
    let db = WechatDb::open(dir.path()).unwrap();

    let result = db
        .query_messages(&MessageQuery::for_talker("wxid_alice").limit(100))
        .unwrap();

    assert_eq!(
        result.stats.skipped, 1,
        "damaged zstd row should be skipped"
    );
    assert!(
        result.items.iter().all(|m| m.sort_seq != 45),
        "damaged row at sort_seq=45 must not appear"
    );
}

#[test]
fn limit_pushdown_invariant_total_rows() {
    let dir = create_limit_pushdown_fixture();
    let db = WechatDb::open(dir.path()).unwrap();

    // With pushdown (no keyword, no filtered_count, no anchor)
    let result = db
        .query_messages(
            &MessageQuery::for_talker("wxid_alice")
                .order(SortOrder::Desc)
                .limit(3),
        )
        .unwrap();

    // With LIMIT pushdown, total_rows reflects scanned rows (may be > items + skipped
    // because each shard fetches offset+limit candidates)
    assert!(
        result.stats.total_rows >= result.items.len() + result.stats.skipped,
        "invariant: total_rows ({}) >= items ({}) + skipped ({})",
        result.stats.total_rows,
        result.items.len(),
        result.stats.skipped
    );

    // Huge offset must not panic or produce negative SQL LIMIT
    let result_huge = db
        .query_messages(
            &MessageQuery::for_talker("wxid_alice")
                .order(SortOrder::Desc)
                .offset(usize::MAX - 1)
                .limit(100),
        )
        .unwrap();
    assert_eq!(result_huge.items.len(), 0, "huge offset returns empty page");

    // Without pushdown (full scan via with_filtered_count)
    let result_full = db
        .query_messages(
            &MessageQuery::for_talker("wxid_alice")
                .with_filtered_count(true)
                .limit(100),
        )
        .unwrap();

    // Full scan without pagination: parsed + skipped == total_rows
    assert_eq!(
        result_full.items.len() + result_full.stats.skipped,
        result_full.stats.total_rows,
        "full scan: parsed + skipped == total_rows"
    );
}

/// Simulates the CLI `query` default path: no keyword, no with_filtered_count, no anchor.
/// Verifies that this path is pushdown-eligible and scans fewer rows than full scan.
#[test]
fn cli_query_default_uses_pushdown() {
    let dir = create_limit_pushdown_fixture();
    let db = WechatDb::open(dir.path()).unwrap();

    // CLI query default path: for_talker + limit + order (no keyword, no with_filtered_count)
    let query_pushdown = MessageQuery::for_talker("wxid_alice")
        .limit(3)
        .order(SortOrder::Desc);
    assert!(
        query_pushdown.limit_pushdown_eligible(),
        "CLI query default path must be pushdown-eligible"
    );

    let result_pushdown = db.query_messages(&query_pushdown).unwrap();

    // Full scan via with_filtered_count(true)
    let result_full = db
        .query_messages(
            &MessageQuery::for_talker("wxid_alice")
                .with_filtered_count(true)
                .limit(3)
                .order(SortOrder::Desc),
        )
        .unwrap();

    // Pushdown scans strictly fewer rows than full scan
    assert!(
        result_pushdown.stats.total_rows < result_full.stats.total_rows,
        "pushdown total_rows ({}) must be < full scan total_rows ({})",
        result_pushdown.stats.total_rows,
        result_full.stats.total_rows
    );

    // Both return the same items (same sort_seq sequence)
    let seqs_pushdown: Vec<i64> = result_pushdown.items.iter().map(|m| m.sort_seq).collect();
    let seqs_full: Vec<i64> = result_full.items.iter().map(|m| m.sort_seq).collect();
    assert_eq!(
        seqs_pushdown, seqs_full,
        "pushdown and full scan must return identical items"
    );
}
