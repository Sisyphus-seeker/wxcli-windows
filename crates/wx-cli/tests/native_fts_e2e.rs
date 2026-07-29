/// End-to-end integration test for the native FTS pipeline.
///
/// Tests the complete path:
///   tokenizer registration (wx_context) →
///   FTS5 MATCH query (rusqlite) →
///   search_message_fts (wx_db) →
///   result enrichment (wx_cli::schema)
///
/// This test lives in wx-cli (which depends on all three lower crates)
/// to avoid introducing a circular dependency between wx-db and wx-context.
use rusqlite::Connection;
use wx_context::register_mm_fts_tokenizer;
use wx_db::native_fts::search_message_fts;

// ---------------------------------------------------------------------------
// Test fixture setup
// ---------------------------------------------------------------------------

fn build_test_db() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    register_mm_fts_tokenizer(&conn).expect("tokenizer registration should succeed");

    // Use real column names matching message_fts.db schema
    conn.execute_batch(
        "CREATE VIRTUAL TABLE message_fts_v4_0 USING fts5(
            acontent, message_local_id UNINDEXED, sort_seq UNINDEXED, local_type UNINDEXED,
            session_id UNINDEXED, sender_id UNINDEXED, create_time UNINDEXED,
            tokenize='MMFtsTokenizer disable_pinyin'
        );
        CREATE VIRTUAL TABLE message_fts_v4_1 USING fts5(
            acontent, message_local_id UNINDEXED, sort_seq UNINDEXED, local_type UNINDEXED,
            session_id UNINDEXED, sender_id UNINDEXED, create_time UNINDEXED,
            tokenize='MMFtsTokenizer disable_pinyin'
        );
        CREATE VIRTUAL TABLE message_fts_v4_2 USING fts5(
            acontent, message_local_id UNINDEXED, sort_seq UNINDEXED, local_type UNINDEXED,
            session_id UNINDEXED, sender_id UNINDEXED, create_time UNINDEXED,
            tokenize='MMFtsTokenizer disable_pinyin'
        );
        CREATE VIRTUAL TABLE message_fts_v4_3 USING fts5(
            acontent, message_local_id UNINDEXED, sort_seq UNINDEXED, local_type UNINDEXED,
            session_id UNINDEXED, sender_id UNINDEXED, create_time UNINDEXED,
            tokenize='MMFtsTokenizer disable_pinyin'
        );
        CREATE TABLE name2id (rowid INTEGER PRIMARY KEY, username TEXT NOT NULL);",
    )
    .unwrap();

    conn
}

#[allow(clippy::too_many_arguments)]
fn insert_msg(
    conn: &Connection,
    shard: usize,
    content: &str,
    sort_seq: i64,
    local_type: i64,
    session_id: i64,
    sender_id: i64,
    create_time: i64,
) {
    let table = format!("message_fts_v4_{shard}");
    conn.execute(
        &format!("INSERT INTO {table}(acontent,message_local_id,sort_seq,local_type,session_id,sender_id,create_time) VALUES(?1,?2,?3,?4,?5,?6,?7)"),
        rusqlite::params![content, 0i64, sort_seq, local_type, session_id, sender_id, create_time],
    )
    .unwrap();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Chinese single-char search ("你") matches messages containing that character.
#[test]
fn chinese_single_char_search() {
    let conn = build_test_db();
    conn.execute_batch(
        "INSERT INTO name2id VALUES (1, 'wxid_alice');
         INSERT INTO name2id VALUES (2, 'wxid_self');",
    )
    .unwrap();
    insert_msg(&conn, 0, "你好世界", 1000, 1, 1, 2, 1700000001);
    insert_msg(&conn, 1, "hello world", 2000, 1, 1, 2, 1700000002);

    let result = search_message_fts(&conn, "你", 10, 0).unwrap();
    assert_eq!(result.total_hits, 1, "Should find Chinese message");
    assert!(result.hits[0].snippet.contains("你"));
}

/// English word search ("hello") matches.
#[test]
fn english_word_search() {
    let conn = build_test_db();
    conn.execute_batch(
        "INSERT INTO name2id VALUES (1, 'wxid_alice');
         INSERT INTO name2id VALUES (2, 'wxid_self');",
    )
    .unwrap();
    insert_msg(&conn, 0, "你好世界", 1000, 1, 1, 2, 1700000001);
    insert_msg(&conn, 1, "hello world", 2000, 1, 1, 2, 1700000002);

    let result = search_message_fts(&conn, "hello", 10, 0).unwrap();
    assert_eq!(result.total_hits, 1, "Should find English message");
    assert!(result.hits[0].snippet.contains("hello"));
}

/// Porter stemming: "running" inserted, searching "run" should match.
#[test]
fn porter_stemming_match() {
    let conn = build_test_db();
    conn.execute_batch(
        "INSERT INTO name2id VALUES (1, 'wxid_alice');
         INSERT INTO name2id VALUES (2, 'wxid_self');",
    )
    .unwrap();
    insert_msg(
        &conn,
        0,
        "I am running fast today",
        1000,
        1,
        1,
        2,
        1700000001,
    );

    // Searching for the stem "run" should match "running"
    let result = search_message_fts(&conn, "run", 10, 0).unwrap();
    assert_eq!(
        result.total_hits, 1,
        "Porter stemming: 'run' should match 'running'"
    );
}

/// Pagination: limit and offset work correctly across multi-shard results.
#[test]
fn pagination_across_shards() {
    let conn = build_test_db();
    conn.execute_batch("INSERT INTO name2id VALUES (1, 'wxid_alice');")
        .unwrap();

    // Insert 6 messages across 4 shards
    for i in 0..6usize {
        insert_msg(
            &conn,
            i % 4,
            "test message content",
            (i as i64) * 100,
            1,
            1,
            1,
            1700000000 + i as i64,
        );
    }

    // All 6
    let all = search_message_fts(&conn, "test", 10, 0).unwrap();
    assert_eq!(all.total_hits, 6);
    assert_eq!(all.hits.len(), 6);

    // First 3
    let page1 = search_message_fts(&conn, "test", 3, 0).unwrap();
    assert_eq!(page1.total_hits, 6);
    assert_eq!(page1.hits.len(), 3);

    // Skip 4, get remaining 2
    let page2 = search_message_fts(&conn, "test", 10, 4).unwrap();
    assert_eq!(page2.total_hits, 6);
    assert_eq!(page2.hits.len(), 2);
}

/// name2id resolution produces correct talker/sender strings.
#[test]
fn name2id_resolution() {
    let conn = build_test_db();
    conn.execute_batch(
        "INSERT INTO name2id VALUES (10, 'wxid_alice');
         INSERT INTO name2id VALUES (20, 'wxid_bob');",
    )
    .unwrap();
    // session_id=10 (talker=wxid_alice), sender_id=20 (sender=wxid_bob)
    insert_msg(&conn, 0, "hello from bob", 1000, 1, 10, 20, 1700000001);

    let result = search_message_fts(&conn, "hello", 10, 0).unwrap();
    assert_eq!(result.hits.len(), 1);
    let hit = &result.hits[0];
    assert_eq!(hit.talker, "wxid_alice");
    assert_eq!(hit.sender, "wxid_bob");
}

/// Result ordering: create_time DESC, sort_seq DESC.
#[test]
fn result_ordering() {
    let conn = build_test_db();
    conn.execute_batch("INSERT INTO name2id VALUES (1, 'wxid_alice');")
        .unwrap();

    // Insert with known create_times
    insert_msg(&conn, 0, "first message hello", 100, 1, 1, 1, 1700000001);
    insert_msg(&conn, 1, "second message hello", 200, 1, 1, 1, 1700000003);
    insert_msg(&conn, 2, "third message hello", 300, 1, 1, 1, 1700000002);

    let result = search_message_fts(&conn, "hello", 10, 0).unwrap();
    assert_eq!(result.hits.len(), 3);
    // Ordered by create_time DESC
    let times: Vec<i64> = result.hits.iter().map(|h| h.create_time).collect();
    assert!(
        times[0] >= times[1] && times[1] >= times[2],
        "Results not ordered by create_time DESC: {times:?}"
    );
}

/// hit_type is Message and server_id is 0 for native FTS results.
#[test]
fn hit_type_and_server_id() {
    let conn = build_test_db();
    conn.execute_batch("INSERT INTO name2id VALUES (1, 'wxid_alice');")
        .unwrap();
    insert_msg(&conn, 0, "hello native fts", 1000, 1, 1, 1, 1700000001);

    let result = search_message_fts(&conn, "hello", 10, 0).unwrap();
    assert_eq!(result.hits.len(), 1);
    let hit = &result.hits[0];
    assert_eq!(hit.server_id, 0, "server_id must be 0 for native FTS");
    assert!(
        matches!(hit.hit_type, wx_db::FtsHitType::Message),
        "hit_type must be Message"
    );
}

/// Mixed CJK + English text: both are searchable.
#[test]
fn mixed_cjk_english() {
    let conn = build_test_db();
    conn.execute_batch("INSERT INTO name2id VALUES (1, 'wxid_alice');")
        .unwrap();
    insert_msg(&conn, 0, "我在用iPhone发消息", 1000, 1, 1, 1, 1700000001);

    // CJK char search
    let r = search_message_fts(&conn, "我", 10, 0).unwrap();
    assert_eq!(r.total_hits, 1, "CJK search should find mixed message");

    // English word search
    let r2 = search_message_fts(&conn, "iphone", 10, 0).unwrap();
    assert_eq!(r2.total_hits, 1, "English search should find mixed message");
}

/// Special character queries (@, [, *) must not trigger fallback (BUG-3 regression guard).
/// After BUG-3 fix, load_name2id() succeeds and the MATCH query executes normally.
/// Results may be empty (no indexed messages contain these chars), but the call must succeed.
#[test]
fn special_char_queries_do_not_fail() {
    let conn = build_test_db();
    conn.execute_batch("INSERT INTO name2id VALUES (1, 'wxid_alice');")
        .unwrap();
    insert_msg(
        &conn,
        0,
        "hello world @user test",
        1000,
        1,
        1,
        1,
        1700000001,
    );
    insert_msg(
        &conn,
        1,
        "this [is] a bracket test",
        2000,
        1,
        1,
        1,
        1700000002,
    );

    // '@' — must not error (BUG-3 fix: load_name2id used to fail before MATCH)
    let r = search_message_fts(&conn, "@", 10, 0);
    assert!(r.is_ok(), "@ query should not fail: {:?}", r.err());

    // '[' — must not error
    let r = search_message_fts(&conn, "[", 10, 0);
    assert!(r.is_ok(), "[ query should not fail: {:?}", r.err());

    // '*' — must not error
    let r = search_message_fts(&conn, "*", 10, 0);
    assert!(r.is_ok(), "* query should not fail: {:?}", r.err());

    // '@user' — can find indexed text containing '@user'
    let r = search_message_fts(&conn, "@user", 10, 0).unwrap();
    assert_eq!(r.total_hits, 1, "@user should match the first message");
}
