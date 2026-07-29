use std::fs;
use std::path::Path;

use rusqlite::{params, Connection};
use tempfile::TempDir;
use wx_db::test_ddl;
use wx_db::{MessageQuery, WechatDb};

// Msg_29a6db07e8bbdb53f5d54cc3c309f3f1  = md5("wxid_alice")
const ALICE_TABLE: &str = "Msg_29a6db07e8bbdb53f5d54cc3c309f3f1";

/// Create a fixture with 2 shards containing messages for wxid_alice.
/// Shard 0 (t=1700000000): sort_seq 100..500, server_id 1001..1005
/// Shard 1 (t=1710000000): sort_seq 600..800, server_id 1006..1008
///
/// Also includes a sort_seq collision: two messages at sort_seq=300
/// with different create_time and server_id.
fn create_anchor_fixture() -> TempDir {
    let dir = TempDir::new().unwrap();
    let base = dir.path();

    // contact/contact.db
    let contact_dir = base.join("contact");
    fs::create_dir_all(&contact_dir).unwrap();
    create_contact_db(&contact_dir.join("contact.db"));

    // session/session.db
    let session_dir = base.join("session");
    fs::create_dir_all(&session_dir).unwrap();
    create_session_db(&session_dir.join("session.db"));

    // message/message_0.db  (shard 0)
    let msg_dir = base.join("message");
    fs::create_dir_all(&msg_dir).unwrap();
    create_shard_0(&msg_dir.join("message_0.db"));

    // message/message_1.db  (shard 1)
    create_shard_1(&msg_dir.join("message_1.db"));

    dir
}

fn create_contact_db(path: &Path) {
    let conn = Connection::open(path).unwrap();
    test_ddl::create_test_contact_table(&conn);
}

fn create_session_db(path: &Path) {
    let conn = Connection::open(path).unwrap();
    test_ddl::create_test_session_table(&conn);
}

fn insert_msg(
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
            1_u32, // local_type = MSG_TYPE_TEXT
            1_i32, // real_sender_id
            create_time,
            text.as_bytes(),
            None::<Vec<u8>>,
            0_i32,
        ],
    )
    .unwrap();
}

/// Shard 0: timestamp=1700000000
/// Messages (sort_seq, server_id, create_time, text):
///   (100, 1001, 1700000100, "msg-1")
///   (200, 1002, 1700000200, "msg-2")
///   (300, 1003, 1700000300, "msg-3a")  ← sort_seq collision
///   (300, 1004, 1700000301, "msg-3b")  ← sort_seq collision (different create_time)
///   (500, 1005, 1700000500, "msg-5")
fn create_shard_0(path: &Path) {
    let conn = Connection::open(path).unwrap();
    conn.execute_batch("CREATE TABLE Timestamp (timestamp INTEGER);")
        .unwrap();
    conn.execute(
        "INSERT INTO Timestamp VALUES (?1)",
        params![1_700_000_000_i64],
    )
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
        );",
        table = ALICE_TABLE
    ))
    .unwrap();

    insert_msg(&conn, ALICE_TABLE, 100, 1001, 1_700_000_100, "msg-1");
    insert_msg(&conn, ALICE_TABLE, 200, 1002, 1_700_000_200, "msg-2");
    insert_msg(&conn, ALICE_TABLE, 300, 1003, 1_700_000_300, "msg-3a");
    insert_msg(&conn, ALICE_TABLE, 300, 1004, 1_700_000_301, "msg-3b");
    insert_msg(&conn, ALICE_TABLE, 500, 1005, 1_700_000_500, "msg-5");
}

/// Shard 1: timestamp=1710000000
/// Messages (sort_seq, server_id, create_time, text):
///   (600, 1006, 1710000100, "msg-6")
///   (700, 1007, 1710000200, "msg-7")
///   (800, 1008, 1710000300, "msg-8")
fn create_shard_1(path: &Path) {
    let conn = Connection::open(path).unwrap();
    conn.execute_batch("CREATE TABLE Timestamp (timestamp INTEGER);")
        .unwrap();
    conn.execute(
        "INSERT INTO Timestamp VALUES (?1)",
        params![1_710_000_000_i64],
    )
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
        );",
        table = ALICE_TABLE
    ))
    .unwrap();

    insert_msg(&conn, ALICE_TABLE, 600, 1006, 1_710_000_100, "msg-6");
    insert_msg(&conn, ALICE_TABLE, 700, 1007, 1_710_000_200, "msg-7");
    insert_msg(&conn, ALICE_TABLE, 800, 1008, 1_710_000_300, "msg-8");
}

// ---------------------------------------------------------------------------
// AfterSortSeq tests
// ---------------------------------------------------------------------------

#[test]
fn after_sort_seq_returns_messages_after_pivot() {
    let dir = create_anchor_fixture();
    let db = WechatDb::open(dir.path()).unwrap();

    let query = MessageQuery::for_talker("wxid_alice")
        .after_sort_seq(300)
        .limit(100);
    let result = db.query_messages_anchor(&query).unwrap();

    let seqs: Vec<i64> = result.items.iter().map(|m| m.sort_seq).collect();
    // Should return sort_seq > 300: 500, 600, 700, 800
    assert_eq!(seqs, vec![500, 600, 700, 800]);
}

#[test]
fn after_sort_seq_respects_limit() {
    let dir = create_anchor_fixture();
    let db = WechatDb::open(dir.path()).unwrap();

    let query = MessageQuery::for_talker("wxid_alice")
        .after_sort_seq(100)
        .limit(2);
    let result = db.query_messages_anchor(&query).unwrap();

    assert_eq!(result.items.len(), 2);
    assert_eq!(result.items[0].sort_seq, 200);
    assert_eq!(result.items[1].sort_seq, 300);
}

#[test]
fn after_sort_seq_applies_filter_before_limit() {
    let dir = create_anchor_fixture();
    let db = WechatDb::open(dir.path()).unwrap();

    // Filter for keyword "msg-5" — only sort_seq=500 matches
    let query = MessageQuery::for_talker("wxid_alice")
        .after_sort_seq(100)
        .keyword("msg-5")
        .limit(100);
    let result = db.query_messages_anchor(&query).unwrap();

    assert_eq!(result.items.len(), 1);
    assert_eq!(result.items[0].sort_seq, 500);
}

#[cfg(unix)]
#[test]
fn pooled_after_sort_seq_works_after_shard_file_removed() {
    let dir = create_anchor_fixture();
    let db = WechatDb::open_with_pool(dir.path(), |_conn| Ok(())).unwrap();

    let shard_path = dir.path().join("message").join("message_1.db");
    fs::remove_file(&shard_path).unwrap();

    let query = MessageQuery::for_talker("wxid_alice")
        .after_sort_seq(300)
        .limit(100);
    let result = db.query_messages_anchor(&query).unwrap();

    let seqs: Vec<i64> = result.items.iter().map(|m| m.sort_seq).collect();
    assert_eq!(seqs, vec![500, 600, 700, 800]);
}

// ---------------------------------------------------------------------------
// AroundSortSeq tests
// ---------------------------------------------------------------------------

#[test]
fn around_sort_seq_basic_context() {
    let dir = create_anchor_fixture();
    let db = WechatDb::open(dir.path()).unwrap();

    let query = MessageQuery::for_talker("wxid_alice")
        .around_sort_seq(500)
        .context(2);
    let result = db.query_messages_anchor(&query).unwrap();

    let seqs: Vec<i64> = result.items.iter().map(|m| m.sort_seq).collect();
    // before(2): [300, 300], pivot: [500], after(2): [600, 700]
    assert_eq!(seqs, vec![300, 300, 500, 600, 700]);
}

#[test]
fn around_sort_seq_collision_pivot_bucket() {
    let dir = create_anchor_fixture();
    let db = WechatDb::open(dir.path()).unwrap();

    // Pivot at sort_seq=300 which has 2 messages (collision)
    let query = MessageQuery::for_talker("wxid_alice")
        .around_sort_seq(300)
        .context(1);
    let result = db.query_messages_anchor(&query).unwrap();

    let seqs: Vec<i64> = result.items.iter().map(|m| m.sort_seq).collect();
    // before(1): [200], pivot bucket: [300, 300], after(1): [500]
    assert_eq!(seqs, vec![200, 300, 300, 500]);

    // Verify pivot bucket is ordered by (create_time, server_id)
    let pivot_msgs: Vec<_> = result.items.iter().filter(|m| m.sort_seq == 300).collect();
    assert_eq!(pivot_msgs.len(), 2);
    assert_eq!(pivot_msgs[0].server_id, 1003);
    assert_eq!(pivot_msgs[1].server_id, 1004);
}

#[test]
fn around_sort_seq_cross_shard_boundary() {
    let dir = create_anchor_fixture();
    let db = WechatDb::open(dir.path()).unwrap();

    // Pivot at sort_seq=500 (shard 0), after should reach into shard 1
    let query = MessageQuery::for_talker("wxid_alice")
        .around_sort_seq(500)
        .context(3);
    let result = db.query_messages_anchor(&query).unwrap();

    let seqs: Vec<i64> = result.items.iter().map(|m| m.sort_seq).collect();
    // before(3): [200, 300, 300], pivot: [500], after(3): [600, 700, 800]
    assert_eq!(seqs, vec![200, 300, 300, 500, 600, 700, 800]);
}

#[test]
fn around_sort_seq_at_start() {
    let dir = create_anchor_fixture();
    let db = WechatDb::open(dir.path()).unwrap();

    // Pivot at the very first sort_seq — no before messages
    let query = MessageQuery::for_talker("wxid_alice")
        .around_sort_seq(100)
        .context(2);
    let result = db.query_messages_anchor(&query).unwrap();

    let seqs: Vec<i64> = result.items.iter().map(|m| m.sort_seq).collect();
    // before: [], pivot: [100], after(2): [200, 300]
    assert_eq!(seqs, vec![100, 200, 300]);
}

#[cfg(unix)]
#[test]
fn pooled_around_sort_seq_works_after_shard_file_removed() {
    let dir = create_anchor_fixture();
    let db = WechatDb::open_with_pool(dir.path(), |_conn| Ok(())).unwrap();

    let shard_path = dir.path().join("message").join("message_0.db");
    fs::remove_file(&shard_path).unwrap();

    let query = MessageQuery::for_talker("wxid_alice")
        .around_sort_seq(500)
        .context(2);
    let result = db.query_messages_anchor(&query).unwrap();

    let seqs: Vec<i64> = result.items.iter().map(|m| m.sort_seq).collect();
    assert_eq!(seqs, vec![300, 300, 500, 600, 700]);
}

// ---------------------------------------------------------------------------
// AroundServerId tests
// ---------------------------------------------------------------------------

#[test]
fn around_server_id_basic() {
    let dir = create_anchor_fixture();
    let db = WechatDb::open(dir.path()).unwrap();

    let query = MessageQuery::for_talker("wxid_alice")
        .around_server_id(1005)
        .context(2);
    let result = db.query_messages_anchor(&query).unwrap();

    let seqs: Vec<i64> = result.items.iter().map(|m| m.sort_seq).collect();
    // pivot=1005 is at sort_seq=500
    // before(2): [300, 300], pivot: [500], after(2): [600, 700]
    assert_eq!(seqs, vec![300, 300, 500, 600, 700]);
}

#[test]
fn around_server_id_with_collision() {
    let dir = create_anchor_fixture();
    let db = WechatDb::open(dir.path()).unwrap();

    // Target server_id=1003 which shares sort_seq=300 with server_id=1004
    let query = MessageQuery::for_talker("wxid_alice")
        .around_server_id(1003)
        .context(1);
    let result = db.query_messages_anchor(&query).unwrap();

    let ids: Vec<i64> = result.items.iter().map(|m| m.server_id).collect();
    // before(1): [1002], pivot: [1003], after(1): [1004]
    // server_id=1004 has same sort_seq but higher create_time, so it's "after" 1003
    assert_eq!(ids, vec![1002, 1003, 1004]);
}

#[test]
fn around_server_id_not_found_returns_empty() {
    let dir = create_anchor_fixture();
    let db = WechatDb::open(dir.path()).unwrap();

    let query = MessageQuery::for_talker("wxid_alice")
        .around_server_id(9999)
        .context(5);
    let result = db.query_messages_anchor(&query).unwrap();

    assert!(result.items.is_empty());
}

#[test]
fn around_server_id_cross_shard() {
    let dir = create_anchor_fixture();
    let db = WechatDb::open(dir.path()).unwrap();

    // server_id=1006 is in shard 1, context should reach back to shard 0
    let query = MessageQuery::for_talker("wxid_alice")
        .around_server_id(1006)
        .context(2);
    let result = db.query_messages_anchor(&query).unwrap();

    let seqs: Vec<i64> = result.items.iter().map(|m| m.sort_seq).collect();
    // before(2): [300, 500] from shard 0, pivot: [600], after(2): [700, 800]
    // Note: 300 appears twice (collision) but LIMIT 2 on the before SQL per shard
    // Shard 0 returns the 2 most recent before pivot: sort_seq=500, then 300
    // Shard 1 has nothing before sort_seq=600 (only 600 itself which is the pivot)
    // Cross-shard merge DESC → [500, 300/300] → take(2) → [500, 300] → reverse → [300, 500]
    // But which 300? The DESC order picks 300(ct=1700000301, sid=1004) first
    assert_eq!(seqs.len(), 5);
    assert_eq!(seqs[0], 300); // or could be 300 (1004)
    assert_eq!(seqs[1], 500);
    assert_eq!(seqs[2], 600); // pivot
    assert_eq!(seqs[3], 700);
    assert_eq!(seqs[4], 800);
}

#[cfg(unix)]
#[test]
fn pooled_around_server_id_works_after_shard_file_removed() {
    let dir = create_anchor_fixture();
    let db = WechatDb::open_with_pool(dir.path(), |_conn| Ok(())).unwrap();

    let shard_path = dir.path().join("message").join("message_1.db");
    fs::remove_file(&shard_path).unwrap();

    let query = MessageQuery::for_talker("wxid_alice")
        .around_server_id(1006)
        .context(2);
    let result = db.query_messages_anchor(&query).unwrap();

    let seqs: Vec<i64> = result.items.iter().map(|m| m.sort_seq).collect();
    assert_eq!(seqs.len(), 5);
    assert_eq!(seqs[0], 300);
    assert_eq!(seqs[1], 500);
    assert_eq!(seqs[2], 600);
    assert_eq!(seqs[3], 700);
    assert_eq!(seqs[4], 800);
}
