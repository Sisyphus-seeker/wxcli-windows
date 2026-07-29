use std::fs;
use std::path::Path;

use rusqlite::{params, Connection};
use tempfile::TempDir;
use wx_db::test_ddl;
use wx_db::{
    encode_packed_info_for_test, MessageContent, MessageQuery, SortOrder, WechatDb, MSG_TYPE_TEXT,
};

// ---- Constants ----

// Msg_29a6db07e8bbdb53f5d54cc3c309f3f1  = md5("wxid_alice")
const ALICE_TABLE: &str = "Msg_29a6db07e8bbdb53f5d54cc3c309f3f1";
// Msg_141611b52b72df07b2e0733d9a36d3c9  = md5("group@chatroom")
const GROUP_TABLE: &str = "Msg_141611b52b72df07b2e0733d9a36d3c9";

// ---- Fixture helpers ----

/// Create the full fixture directory with 2 message shards, contact.db, and session.db.
fn create_fixture() -> TempDir {
    let dir = TempDir::new().unwrap();
    let base = dir.path();

    // contact/contact.db  (minimal, required by WechatDb::open)
    let contact_dir = base.join("contact");
    fs::create_dir_all(&contact_dir).unwrap();
    create_contact_db(&contact_dir.join("contact.db"));

    // session/session.db  (minimal, required by WechatDb::open)
    let session_dir = base.join("session");
    fs::create_dir_all(&session_dir).unwrap();
    create_session_db(&session_dir.join("session.db"));

    // message/message_0.db  (shard 0: timestamp=1700000000, HAS WCDB_CT column)
    let msg_dir = base.join("message");
    fs::create_dir_all(&msg_dir).unwrap();
    create_shard_0(&msg_dir.join("message_0.db"));

    // message/message_1.db  (shard 1: timestamp=1710000000, NO WCDB_CT column)
    create_shard_1(&msg_dir.join("message_1.db"));

    dir
}

fn create_contact_db(path: &Path) {
    let conn = Connection::open(path).unwrap();
    test_ddl::create_test_contact_table(&conn);
    conn.execute(
        "INSERT INTO contact (username, alias, remark, nick_name) VALUES (?1, ?2, ?3, ?4)",
        params!["wxid_alice", "", "", "Alice"],
    )
    .unwrap();
}

fn create_session_db(path: &Path) {
    let conn = Connection::open(path).unwrap();
    test_ddl::create_test_session_table(&conn);
}

/// Shard 0: timestamp=1700000000, HAS WCDB_CT_message_content column.
/// Contains:
///   - Name2Id: alice (rowid=1), bob (rowid=2)
///   - Msg table for "wxid_alice" with 3 messages + 1 damaged zstd message
fn create_shard_0(path: &Path) {
    let conn = Connection::open(path).unwrap();

    // Timestamp table
    conn.execute_batch("CREATE TABLE Timestamp (timestamp INTEGER);")
        .unwrap();
    conn.execute(
        "INSERT INTO Timestamp VALUES (?1)",
        params![1_700_000_000_i64],
    )
    .unwrap();

    // Name2Id table
    conn.execute_batch(
        "CREATE TABLE Name2Id (
            rowid INTEGER PRIMARY KEY,
            user_name TEXT
        );",
    )
    .unwrap();
    conn.execute(
        "INSERT INTO Name2Id VALUES (?1, ?2)",
        params![1, "wxid_alice"],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO Name2Id VALUES (?1, ?2)",
        params![2, "wxid_bob"],
    )
    .unwrap();

    // Msg table for wxid_alice — WITH WCDB_CT column
    conn.execute_batch(&format!(
        "CREATE TABLE [{table}] (
            sort_seq INTEGER,
            server_id INTEGER,
            local_type INTEGER,
            real_sender_id INTEGER,
            create_time INTEGER,
            message_content BLOB,
            packed_info_data BLOB,
            status INTEGER,
            WCDB_CT_message_content INTEGER
        );",
        table = ALICE_TABLE
    ))
    .unwrap();

    // Message 1: plain text, type=1 (text), sender=alice (rowid=1)
    conn.execute(
        &format!(
            "INSERT INTO [{table}] VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            table = ALICE_TABLE
        ),
        params![
            100_i64,                 // sort_seq
            1001_i64,                // server_id
            1_u32,                   // local_type = MSG_TYPE_TEXT
            1_i32,                   // real_sender_id → Name2Id rowid=1 → "wxid_alice"
            1_700_000_100_i64,       // create_time
            b"hello world" as &[u8], // message_content (plain text)
            None::<Vec<u8>>,         // packed_info_data
            0_i32,                   // status
            None::<i32>,             // WCDB_CT_message_content (NULL = not compressed)
        ],
    )
    .unwrap();

    // Message 2: zstd compressed text (CT=4), type=1 (text), sender=bob (rowid=2)
    let compressed = zstd::encode_all(&b"compressed message content"[..], 0).unwrap();
    conn.execute(
        &format!(
            "INSERT INTO [{table}] VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            table = ALICE_TABLE
        ),
        params![
            200_i64,           // sort_seq
            1002_i64,          // server_id
            1_u32,             // local_type = MSG_TYPE_TEXT
            2_i32,             // real_sender_id → Name2Id rowid=2 → "wxid_bob"
            1_700_000_200_i64, // create_time
            compressed,        // message_content (zstd compressed)
            None::<Vec<u8>>,   // packed_info_data
            0_i32,             // status
            4_i32,             // WCDB_CT_message_content = 4 → zstd
        ],
    )
    .unwrap();

    // Message 3: image with packed_info, type=3 (image), sender=alice (rowid=1)
    let packed_bytes = encode_packed_info_for_test(Some("abc123def456"), None);
    conn.execute(
        &format!(
            "INSERT INTO [{table}] VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            table = ALICE_TABLE
        ),
        params![
            300_i64,           // sort_seq
            1003_i64,          // server_id
            3_u32,             // local_type = MSG_TYPE_IMAGE
            1_i32,             // real_sender_id
            1_700_000_300_i64, // create_time
            b"" as &[u8],      // message_content (empty for image)
            packed_bytes,      // packed_info_data
            0_i32,             // status
            None::<i32>,       // WCDB_CT_message_content
        ],
    )
    .unwrap();

    // Message 4: DAMAGED zstd message — should be skipped
    // Starts with zstd magic but is corrupted
    let damaged_zstd: Vec<u8> = vec![0x28, 0xB5, 0x2F, 0xFD, 0xFF, 0xFF, 0xFF];
    conn.execute(
        &format!(
            "INSERT INTO [{table}] VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            table = ALICE_TABLE
        ),
        params![
            400_i64,           // sort_seq
            1004_i64,          // server_id
            1_u32,             // local_type = MSG_TYPE_TEXT
            1_i32,             // real_sender_id
            1_700_000_400_i64, // create_time
            damaged_zstd,      // message_content (damaged zstd)
            None::<Vec<u8>>,   // packed_info_data
            0_i32,             // status
            4_i32,             // WCDB_CT = 4 → forces zstd decode attempt
        ],
    )
    .unwrap();

    // Message 5: app link message, type=49 sub_type=5, local_type = (5 << 32) | 49
    let link_xml = r#"<msg><appmsg><title><![CDATA[Test Article]]></title><des>Article description</des><url>https://mp.weixin.qq.com/test</url></appmsg></msg>"#;
    conn.execute(
        &format!(
            "INSERT INTO [{table}] VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            table = ALICE_TABLE
        ),
        params![
            500_i64,             // sort_seq
            1005_i64,            // server_id
            (5_i64 << 32) | 49,  // local_type = (5 << 32) | 49 → msg_type=49, sub_type=5
            1_i32,               // real_sender_id → alice
            1_700_000_500_i64,   // create_time
            link_xml.as_bytes(), // message_content (XML)
            None::<Vec<u8>>,     // packed_info_data
            0_i32,               // status
            None::<i32>,         // WCDB_CT_message_content
        ],
    )
    .unwrap();
}

/// Shard 1: timestamp=1710000000, NO WCDB_CT_message_content column.
/// Contains:
///   - Name2Id: charlie (rowid=1)
///   - Msg table for "group@chatroom" with 2 group messages
fn create_shard_1(path: &Path) {
    let conn = Connection::open(path).unwrap();

    // Timestamp table
    conn.execute_batch("CREATE TABLE Timestamp (timestamp INTEGER);")
        .unwrap();
    conn.execute(
        "INSERT INTO Timestamp VALUES (?1)",
        params![1_710_000_000_i64],
    )
    .unwrap();

    // Name2Id table
    conn.execute_batch(
        "CREATE TABLE Name2Id (
            rowid INTEGER PRIMARY KEY,
            user_name TEXT
        );",
    )
    .unwrap();
    conn.execute(
        "INSERT INTO Name2Id VALUES (?1, ?2)",
        params![1, "wxid_charlie"],
    )
    .unwrap();

    // Msg table for group@chatroom — WITHOUT WCDB_CT column
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
        table = GROUP_TABLE
    ))
    .unwrap();

    // Message 1: group message, plain text with sender prefix
    let group_msg_1 = b"wxid_sender_a:\nhello from group";
    conn.execute(
        &format!(
            "INSERT INTO [{table}] VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            table = GROUP_TABLE
        ),
        params![
            500_i64,           // sort_seq
            2001_i64,          // server_id
            1_u32,             // local_type = MSG_TYPE_TEXT
            1_i32,             // real_sender_id → charlie
            1_710_000_100_i64, // create_time
            &group_msg_1[..],  // message_content
            None::<Vec<u8>>,   // packed_info_data
            0_i32,             // status
        ],
    )
    .unwrap();

    // Message 2: group message, zstd compressed (detected by magic bytes, no CT column)
    let group_content = b"wxid_sender_b:\ncompressed group message";
    let compressed = zstd::encode_all(&group_content[..], 0).unwrap();
    conn.execute(
        &format!(
            "INSERT INTO [{table}] VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            table = GROUP_TABLE
        ),
        params![
            600_i64,           // sort_seq
            2002_i64,          // server_id
            1_u32,             // local_type = MSG_TYPE_TEXT
            1_i32,             // real_sender_id → charlie
            1_710_000_200_i64, // create_time
            compressed,        // message_content (zstd compressed, magic bytes detection)
            None::<Vec<u8>>,   // packed_info_data
            0_i32,             // status
        ],
    )
    .unwrap();
}

// ---- Tests ----

#[test]
fn messages_routing_alice_query_hits_shard_0_only() {
    let dir = create_fixture();
    let db = WechatDb::open(dir.path()).unwrap();

    // Query for wxid_alice with time range covering only shard 0
    let result = db
        .query_messages(
            &MessageQuery::for_talker("wxid_alice").time_range(1_700_000_000, 1_709_999_999),
        )
        .unwrap();

    // 5 rows total (4 valid + 1 damaged), 4 decoded, 1 skipped
    assert_eq!(result.items.len(), 4, "expected 4 valid messages");
    assert_eq!(
        result.stats.total_rows, 5,
        "expected 5 total rows (incl damaged)"
    );
    assert_eq!(result.stats.skipped, 1, "expected 1 skipped (damaged zstd)");
    assert_eq!(
        result.items.len() + result.stats.skipped,
        result.stats.total_rows,
        "invariant: parsed + skipped == total_rows"
    );
}

#[test]
fn messages_routing_zstd_decompression_with_ct_column() {
    let dir = create_fixture();
    let db = WechatDb::open(dir.path()).unwrap();

    let result = db
        .query_messages(
            &MessageQuery::for_talker("wxid_alice").time_range(1_700_000_000, 1_709_999_999),
        )
        .unwrap();

    // Message at sort_seq=200 should be decompressed from zstd (CT=4)
    let msg = result.items.iter().find(|m| m.sort_seq == 200).unwrap();
    match &msg.content {
        MessageContent::Text(s) => assert_eq!(s, "compressed message content"),
        other => panic!("expected Text, got: {:?}", other),
    }
    assert_eq!(
        result.items.len() + result.stats.skipped,
        result.stats.total_rows,
        "invariant: parsed + skipped == total_rows"
    );
}

#[test]
fn messages_routing_plain_text_message() {
    let dir = create_fixture();
    let db = WechatDb::open(dir.path()).unwrap();

    let result = db
        .query_messages(
            &MessageQuery::for_talker("wxid_alice").time_range(1_700_000_000, 1_709_999_999),
        )
        .unwrap();

    // Message at sort_seq=100 should be plain text
    let msg = result.items.iter().find(|m| m.sort_seq == 100).unwrap();
    match &msg.content {
        MessageContent::Text(s) => assert_eq!(s, "hello world"),
        other => panic!("expected Text, got: {:?}", other),
    }
    assert_eq!(
        result.items.len() + result.stats.skipped,
        result.stats.total_rows,
        "invariant: parsed + skipped == total_rows"
    );
}

#[test]
fn messages_routing_name2id_sender_resolved() {
    let dir = create_fixture();
    let db = WechatDb::open(dir.path()).unwrap();

    let result = db
        .query_messages(
            &MessageQuery::for_talker("wxid_alice").time_range(1_700_000_000, 1_709_999_999),
        )
        .unwrap();

    // sort_seq=100: real_sender_id=1 → Name2Id "wxid_alice"
    let msg100 = result.items.iter().find(|m| m.sort_seq == 100).unwrap();
    assert_eq!(msg100.sender, "wxid_alice");

    // sort_seq=200: real_sender_id=2 → Name2Id "wxid_bob"
    let msg200 = result.items.iter().find(|m| m.sort_seq == 200).unwrap();
    assert_eq!(msg200.sender, "wxid_bob");
    assert_eq!(
        result.items.len() + result.stats.skipped,
        result.stats.total_rows,
        "invariant: parsed + skipped == total_rows"
    );
}

#[test]
fn messages_routing_image_packed_info_md5() {
    let dir = create_fixture();
    let db = WechatDb::open(dir.path()).unwrap();

    let result = db
        .query_messages(
            &MessageQuery::for_talker("wxid_alice").time_range(1_700_000_000, 1_709_999_999),
        )
        .unwrap();

    // sort_seq=300: image message with packed_info containing image_md5
    let msg = result.items.iter().find(|m| m.sort_seq == 300).unwrap();
    assert_eq!(msg.msg_type, 3); // MSG_TYPE_IMAGE
    match &msg.content {
        MessageContent::Image { md5 } => {
            assert_eq!(md5.as_deref(), Some("abc123def456"));
        }
        other => panic!("expected Image, got: {:?}", other),
    }
    assert_eq!(
        result.items.len() + result.stats.skipped,
        result.stats.total_rows,
        "invariant: parsed + skipped == total_rows"
    );
}

#[test]
fn messages_routing_group_sender_from_content() {
    let dir = create_fixture();
    let db = WechatDb::open(dir.path()).unwrap();

    let result = db
        .query_messages(
            &MessageQuery::for_talker("group@chatroom").time_range(1_710_000_000, 1_719_999_999),
        )
        .unwrap();

    assert_eq!(result.items.len(), 2);

    // sort_seq=500: sender extracted from "wxid_sender_a:\nhello from group"
    let msg500 = result.items.iter().find(|m| m.sort_seq == 500).unwrap();
    assert_eq!(msg500.sender, "wxid_sender_a");
    match &msg500.content {
        MessageContent::Text(s) => assert_eq!(s, "hello from group"),
        other => panic!("expected Text, got: {:?}", other),
    }

    // sort_seq=600: zstd compressed, sender from "wxid_sender_b:\ncompressed group message"
    let msg600 = result.items.iter().find(|m| m.sort_seq == 600).unwrap();
    assert_eq!(msg600.sender, "wxid_sender_b");
    match &msg600.content {
        MessageContent::Text(s) => assert_eq!(s, "compressed group message"),
        other => panic!("expected Text, got: {:?}", other),
    }
    assert_eq!(
        result.items.len() + result.stats.skipped,
        result.stats.total_rows,
        "invariant: parsed + skipped == total_rows"
    );
}

#[test]
fn messages_routing_no_wcdb_ct_column_works() {
    let dir = create_fixture();
    let db = WechatDb::open(dir.path()).unwrap();

    // Shard 1 has no WCDB_CT column — should still work fine
    let result = db
        .query_messages(
            &MessageQuery::for_talker("group@chatroom").time_range(1_710_000_000, 1_719_999_999),
        )
        .unwrap();

    assert_eq!(result.items.len(), 2);
    assert_eq!(result.stats.skipped, 0);
    assert_eq!(
        result.items.len() + result.stats.skipped,
        result.stats.total_rows,
        "invariant: parsed + skipped == total_rows"
    );
}

#[test]
fn messages_routing_keyword_filter() {
    let dir = create_fixture();
    let db = WechatDb::open(dir.path()).unwrap();

    // "hello" should match message at sort_seq=100 ("hello world")
    let result = db
        .query_messages(
            &MessageQuery::for_talker("wxid_alice")
                .time_range(1_700_000_000, 1_709_999_999)
                .keyword("hello"),
        )
        .unwrap();

    assert_eq!(result.items.len(), 1);
    assert_eq!(result.items[0].sort_seq, 100);
    assert!(
        result.stats.total_rows >= result.items.len() + result.stats.skipped,
        "total_rows must be >= parsed + skipped"
    );
}

#[test]
fn messages_routing_keyword_filter_case_insensitive() {
    let dir = create_fixture();
    let db = WechatDb::open(dir.path()).unwrap();

    // "HELLO" should match case-insensitively
    let result = db
        .query_messages(
            &MessageQuery::for_talker("wxid_alice")
                .time_range(1_700_000_000, 1_709_999_999)
                .keyword("HELLO"),
        )
        .unwrap();

    assert_eq!(result.items.len(), 1);
    assert_eq!(result.items[0].sort_seq, 100);
    assert!(
        result.stats.total_rows >= result.items.len() + result.stats.skipped,
        "total_rows must be >= parsed + skipped"
    );
}

#[test]
fn messages_routing_limit_offset_pagination() {
    let dir = create_fixture();
    let db = WechatDb::open(dir.path()).unwrap();

    // Limit=1: should get only the first message (ASC order)
    let result = db
        .query_messages(
            &MessageQuery::for_talker("wxid_alice")
                .time_range(1_700_000_000, 1_709_999_999)
                .order(SortOrder::Asc)
                .limit(1),
        )
        .unwrap();
    assert_eq!(result.items.len(), 1);
    assert_eq!(result.items[0].sort_seq, 100);

    // Offset=1, Limit=1: should get the second message
    let result = db
        .query_messages(
            &MessageQuery::for_talker("wxid_alice")
                .time_range(1_700_000_000, 1_709_999_999)
                .order(SortOrder::Asc)
                .limit(1)
                .offset(1),
        )
        .unwrap();
    assert_eq!(result.items.len(), 1);
    assert_eq!(result.items[0].sort_seq, 200);

    // Offset=2, Limit=10: should get messages 3 and 5 (sort_seq 300, 500)
    let result = db
        .query_messages(
            &MessageQuery::for_talker("wxid_alice")
                .time_range(1_700_000_000, 1_709_999_999)
                .order(SortOrder::Asc)
                .limit(10)
                .offset(2),
        )
        .unwrap();
    assert_eq!(result.items.len(), 2);
    assert_eq!(result.items[0].sort_seq, 300);
    assert_eq!(result.items[1].sort_seq, 500);
    assert!(
        result.stats.total_rows >= result.items.len() + result.stats.skipped,
        "total_rows must be >= parsed + skipped"
    );
}

#[test]
fn messages_routing_sorted_by_sort_seq_asc() {
    let dir = create_fixture();
    let db = WechatDb::open(dir.path()).unwrap();

    let result = db
        .query_messages(
            &MessageQuery::for_talker("wxid_alice")
                .time_range(1_700_000_000, 1_709_999_999)
                .order(SortOrder::Asc),
        )
        .unwrap();

    // Verify ascending sort_seq order
    let seqs: Vec<i64> = result.items.iter().map(|m| m.sort_seq).collect();
    assert_eq!(seqs, vec![100, 200, 300, 500]);
    assert_eq!(
        result.items.len() + result.stats.skipped,
        result.stats.total_rows,
        "invariant: parsed + skipped == total_rows"
    );
}

#[test]
fn messages_routing_damaged_zstd_skipped() {
    let dir = create_fixture();
    let db = WechatDb::open(dir.path()).unwrap();

    let result = db
        .query_messages(
            &MessageQuery::for_talker("wxid_alice").time_range(1_700_000_000, 1_709_999_999),
        )
        .unwrap();

    // Damaged zstd message (sort_seq=400) should be skipped
    assert_eq!(result.stats.skipped, 1);
    assert!(
        result.items.iter().all(|m| m.sort_seq != 400),
        "damaged message should not appear in results"
    );
    assert_eq!(
        result.items.len() + result.stats.skipped,
        result.stats.total_rows,
        "invariant: parsed + skipped == total_rows"
    );
}

#[test]
fn messages_routing_table_not_in_shard_skips_gracefully() {
    let dir = create_fixture();
    let db = WechatDb::open(dir.path()).unwrap();

    // Query for a talker that has no Msg table in any shard
    let result = db
        .query_messages(&MessageQuery::for_talker("nonexistent_wxid"))
        .unwrap();

    assert_eq!(result.items.len(), 0);
    assert_eq!(result.stats.total_rows, 0);
    assert_eq!(result.stats.skipped, 0);
    assert_eq!(
        result.items.len() + result.stats.skipped,
        result.stats.total_rows,
        "invariant: parsed + skipped == total_rows"
    );
}

#[test]
fn messages_routing_zstd_magic_bytes_detection_no_ct() {
    let dir = create_fixture();
    let db = WechatDb::open(dir.path()).unwrap();

    // Shard 1 has no CT column but message 2 is zstd-compressed;
    // should be detected via magic bytes
    let result = db
        .query_messages(
            &MessageQuery::for_talker("group@chatroom").time_range(1_710_000_000, 1_719_999_999),
        )
        .unwrap();

    let msg600 = result.items.iter().find(|m| m.sort_seq == 600).unwrap();
    match &msg600.content {
        MessageContent::Text(s) => assert_eq!(s, "compressed group message"),
        other => panic!("expected Text, got: {:?}", other),
    }
    assert_eq!(
        result.items.len() + result.stats.skipped,
        result.stats.total_rows,
        "invariant: parsed + skipped == total_rows"
    );
}

#[test]
fn messages_routing_cross_shard_merge_sorted() {
    // Create a fixture where the same talker has messages in both shards
    let dir = TempDir::new().unwrap();
    let base = dir.path();

    // contact/contact.db
    let contact_dir = base.join("contact");
    fs::create_dir_all(&contact_dir).unwrap();
    {
        let conn = Connection::open(contact_dir.join("contact.db")).unwrap();
        test_ddl::create_test_contact_table_minimal(&conn);
    }

    // session/session.db
    let session_dir = base.join("session");
    fs::create_dir_all(&session_dir).unwrap();
    {
        let conn = Connection::open(session_dir.join("session.db")).unwrap();
        test_ddl::create_test_session_table(&conn);
    }

    let msg_dir = base.join("message");
    fs::create_dir_all(&msg_dir).unwrap();

    // Shard 0: timestamp=1700000000
    {
        let conn = Connection::open(msg_dir.join("message_0.db")).unwrap();
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
            params![1, "wxid_cross"],
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
        conn.execute(
            &format!(
                "INSERT INTO [{table}] VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                table = ALICE_TABLE
            ),
            params![
                10_i64,
                1_i64,
                1_u32,
                1_i32,
                1_700_000_100_i64,
                b"shard0 msg" as &[u8],
                None::<Vec<u8>>,
                0_i32,
            ],
        )
        .unwrap();
    }

    // Shard 1: timestamp=1710000000
    {
        let conn = Connection::open(msg_dir.join("message_1.db")).unwrap();
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
            params![1, "wxid_cross"],
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
        conn.execute(
            &format!(
                "INSERT INTO [{table}] VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                table = ALICE_TABLE
            ),
            params![
                5_i64,
                2_i64,
                1_u32,
                1_i32,
                1_710_000_100_i64,
                b"shard1 msg" as &[u8],
                None::<Vec<u8>>,
                0_i32,
            ],
        )
        .unwrap();
    }

    let db = WechatDb::open(base).unwrap();
    let result = db
        .query_messages(&MessageQuery::for_talker("wxid_alice").order(SortOrder::Asc))
        .unwrap();

    // Both messages found, sorted by sort_seq ASC (5 before 10)
    assert_eq!(result.items.len(), 2);
    assert_eq!(result.items[0].sort_seq, 5);
    assert_eq!(result.items[1].sort_seq, 10);
    assert_eq!(
        result.items.len() + result.stats.skipped,
        result.stats.total_rows,
        "invariant: parsed + skipped == total_rows"
    );
}

#[test]
fn messages_routing_sorted_by_sort_seq_desc() {
    let dir = create_fixture();
    let db = WechatDb::open(dir.path()).unwrap();

    // Default order is Desc
    let result = db
        .query_messages(
            &MessageQuery::for_talker("wxid_alice").time_range(1_700_000_000, 1_709_999_999),
        )
        .unwrap();

    let seqs: Vec<i64> = result.items.iter().map(|m| m.sort_seq).collect();
    assert_eq!(seqs, vec![500, 300, 200, 100]);
    assert_eq!(
        result.items.len() + result.stats.skipped,
        result.stats.total_rows,
        "invariant: parsed + skipped == total_rows"
    );
}

#[test]
fn messages_routing_msg_type_filter() {
    let dir = create_fixture();
    let db = WechatDb::open(dir.path()).unwrap();

    // Filter text messages only (sort_seq 100, 200 are text; 300 is image)
    let result = db
        .query_messages(
            &MessageQuery::for_talker("wxid_alice")
                .time_range(1_700_000_000, 1_709_999_999)
                .msg_type(MSG_TYPE_TEXT)
                .with_filtered_count(true),
        )
        .unwrap();

    assert_eq!(result.items.len(), 2);
    assert!(result.items.iter().all(|m| m.msg_type == MSG_TYPE_TEXT));
    assert_eq!(result.stats.filtered_count, Some(2));
    assert!(
        result.stats.total_rows >= result.items.len() + result.stats.skipped,
        "total_rows must be >= parsed + skipped"
    );
}

#[test]
fn messages_routing_filtered_count_without_opt_in() {
    let dir = create_fixture();
    let db = WechatDb::open(dir.path()).unwrap();

    // without with_filtered_count, filtered_count is None
    let result = db
        .query_messages(
            &MessageQuery::for_talker("wxid_alice").time_range(1_700_000_000, 1_709_999_999),
        )
        .unwrap();

    assert_eq!(result.stats.filtered_count, None);
    assert_eq!(
        result.items.len() + result.stats.skipped,
        result.stats.total_rows,
        "invariant: parsed + skipped == total_rows"
    );
}

#[test]
fn messages_routing_keyword_with_filtered_count() {
    let dir = create_fixture();
    let db = WechatDb::open(dir.path()).unwrap();

    let result = db
        .query_messages(
            &MessageQuery::for_talker("wxid_alice")
                .time_range(1_700_000_000, 1_709_999_999)
                .keyword("hello")
                .with_filtered_count(true),
        )
        .unwrap();

    assert_eq!(result.items.len(), 1);
    assert_eq!(result.stats.filtered_count, Some(1));
    assert!(
        result.stats.total_rows >= result.items.len() + result.stats.skipped,
        "total_rows must be >= parsed + skipped"
    );
}

#[test]
fn messages_routing_link_message_decoded() {
    let dir = create_fixture();
    let db = WechatDb::open(dir.path()).unwrap();

    let result = db
        .query_messages(
            &MessageQuery::for_talker("wxid_alice").time_range(1_700_000_000, 1_709_999_999),
        )
        .unwrap();

    // sort_seq=500: app link message (type=49, sub_type=5)
    let msg = result.items.iter().find(|m| m.sort_seq == 500).unwrap();
    assert_eq!(msg.msg_type, 49);
    assert_eq!(msg.sub_type, 5);
    match &msg.content {
        MessageContent::Link {
            title, url, des, ..
        } => {
            assert_eq!(title.as_deref(), Some("Test Article"));
            assert_eq!(url.as_deref(), Some("https://mp.weixin.qq.com/test"));
            assert_eq!(des.as_deref(), Some("Article description"));
        }
        other => panic!("expected Link, got: {:?}", other),
    }
    assert_eq!(
        result.items.len() + result.stats.skipped,
        result.stats.total_rows,
        "invariant: parsed + skipped == total_rows"
    );
}

#[test]
fn messages_routing_keyword_matches_link_title() {
    let dir = create_fixture();
    let db = WechatDb::open(dir.path()).unwrap();

    // "Article" should match the link message title
    let result = db
        .query_messages(
            &MessageQuery::for_talker("wxid_alice")
                .time_range(1_700_000_000, 1_709_999_999)
                .keyword("Article"),
        )
        .unwrap();

    assert_eq!(result.items.len(), 1);
    assert_eq!(result.items[0].sort_seq, 500);
    assert!(
        result.stats.total_rows >= result.items.len() + result.stats.skipped,
        "total_rows must be >= parsed + skipped"
    );
}

#[test]
fn messages_routing_compress_content_quote_decoded() {
    // Build a custom fixture with compress_content column
    let dir = TempDir::new().unwrap();
    let base = dir.path();

    // Minimal contact.db
    let contact_dir = base.join("contact");
    fs::create_dir_all(&contact_dir).unwrap();
    {
        let conn = Connection::open(contact_dir.join("contact.db")).unwrap();
        test_ddl::create_test_contact_table_minimal(&conn);
    }

    // Minimal session.db
    let session_dir = base.join("session");
    fs::create_dir_all(&session_dir).unwrap();
    {
        let conn = Connection::open(session_dir.join("session.db")).unwrap();
        test_ddl::create_test_session_table(&conn);
    }

    let msg_dir = base.join("message");
    fs::create_dir_all(&msg_dir).unwrap();

    // Shard with compress_content column
    {
        let conn = Connection::open(msg_dir.join("message_0.db")).unwrap();
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

        // Create table WITH compress_content column
        conn.execute_batch(&format!(
            "CREATE TABLE [{table}] (
                sort_seq INTEGER,
                server_id INTEGER,
                local_type INTEGER,
                real_sender_id INTEGER,
                create_time INTEGER,
                message_content BLOB,
                packed_info_data BLOB,
                status INTEGER,
                WCDB_CT_message_content INTEGER,
                compress_content BLOB
            );",
            table = ALICE_TABLE
        ))
        .unwrap();

        // Quote message: type=49/sub_type=57, local_type = (57 << 32) | 49
        // message_content is empty placeholder; real XML is in compress_content (zstd)
        let quote_xml = r#"<msg><appmsg><title>reply text here</title><refermsg><fromusr>wxid_bob</fromusr><displayname>Bob</displayname><content>original quoted text</content><type>1</type></refermsg></appmsg></msg>"#;
        let compressed = zstd::encode_all(quote_xml.as_bytes(), 0).unwrap();

        conn.execute(
            &format!(
                "INSERT INTO [{table}] VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                table = ALICE_TABLE
            ),
            params![
                100_i64,             // sort_seq
                5001_i64,            // server_id
                (57_i64 << 32) | 49, // local_type = (57 << 32) | 49
                1_i32,               // real_sender_id
                1_700_000_100_i64,   // create_time
                b"" as &[u8],        // message_content (empty)
                None::<Vec<u8>>,     // packed_info_data
                0_i32,               // status
                None::<i32>,         // WCDB_CT
                compressed,          // compress_content (zstd)
            ],
        )
        .unwrap();
    }

    let db = WechatDb::open(base).unwrap();
    let result = db
        .query_messages(
            &MessageQuery::for_talker("wxid_alice").time_range(1_700_000_000, 1_709_999_999),
        )
        .unwrap();

    assert_eq!(result.items.len(), 1);
    let msg = &result.items[0];
    assert_eq!(msg.msg_type, 49);
    assert_eq!(msg.sub_type, 57);
    match &msg.content {
        MessageContent::Quote {
            reply_text,
            refer_sender,
            refer_content,
            refer_type,
            ..
        } => {
            assert_eq!(reply_text.as_deref(), Some("reply text here"));
            assert_eq!(refer_sender.as_deref(), Some("Bob"));
            assert_eq!(refer_content.as_deref(), Some("original quoted text"));
            assert_eq!(*refer_type, Some(1));
        }
        other => panic!("expected Quote, got: {:?}", other),
    }
    assert_eq!(
        result.items.len() + result.stats.skipped,
        result.stats.total_rows,
        "invariant: parsed + skipped == total_rows"
    );
}

// ---------------------------------------------------------------------------
// bulk_max_sort_seq
// ---------------------------------------------------------------------------

#[test]
fn bulk_max_sort_seq_known_session_without_msg_table_returns_zero() {
    let dir = create_fixture();
    let db = WechatDb::open(dir.path()).unwrap();

    // "wxid_nobody" has no Msg_* table in any shard, but is a "known" session
    let usernames = vec!["wxid_nobody".to_string()];
    let result = db.bulk_max_sort_seq(&usernames);

    assert_eq!(
        result.get("wxid_nobody"),
        Some(&0),
        "known session without Msg_* table should return baseline 0"
    );
}

#[test]
fn bulk_max_sort_seq_returns_max_across_shards() {
    let dir = create_fixture();
    let db = WechatDb::open(dir.path()).unwrap();

    let usernames = vec!["wxid_alice".to_string(), "group@chatroom".to_string()];
    let result = db.bulk_max_sort_seq(&usernames);

    // wxid_alice: shard 0 has messages with sort_seq 100, 200, 300, 400 (damaged), 500 (link)
    let alice_max = *result.get("wxid_alice").unwrap();
    assert_eq!(
        alice_max, 500,
        "should get max sort_seq across all rows in shard"
    );

    // group@chatroom: shard 1 has messages with sort_seq 500, 600
    let group_max = *result.get("group@chatroom").unwrap();
    assert_eq!(group_max, 600, "should get max sort_seq from shard 1");
}

#[test]
fn bulk_max_sort_seq_empty_input_returns_empty() {
    let dir = create_fixture();
    let db = WechatDb::open(dir.path()).unwrap();

    let result = db.bulk_max_sort_seq(&[]);
    assert!(result.is_empty());
}
