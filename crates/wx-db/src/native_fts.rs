use std::collections::HashMap;

use rusqlite::Connection;
use serde::Serialize;

use crate::error::DbError;
use crate::fts::build_fts_query;
use crate::model::split_local_type;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// The type of content hit (message or contact).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FtsHitType {
    Message,
    Contact,
}

/// A single hit from native FTS search.
#[derive(Debug, Clone, Serialize)]
pub struct NativeFtsHit {
    /// Hit type — always `Message` for Task 3 results.
    pub hit_type: FtsHitType,
    /// Resolved wxid or chatroom identifier, via name2id table.
    pub talker: String,
    /// Resolved wxid of the sender, via name2id table.
    pub sender: String,
    /// Raw message content text (acontent column verbatim).
    pub snippet: String,
    /// Unix seconds creation time.
    pub create_time: i64,
    /// Millisecond sort sequence.
    pub sort_seq: i64,
    /// Message local ID (c1), used as unique tie-breaker for stable pagination.
    pub message_local_id: i64,
    /// Primary message type (lower 32 bits of local_type).
    pub msg_type: u32,
    /// Message sub-type (upper 32 bits of local_type).
    pub sub_type: u32,
    /// Always `0` for native FTS results (breaking change — see plan).
    pub server_id: i64,
}

/// Result of a native FTS search operation.
#[derive(Debug, Clone)]
pub struct NativeFtsResult {
    pub hits: Vec<NativeFtsHit>,
    /// Total matched rows (before limit/offset).
    pub total_hits: usize,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Load the `name2id` lookup table from the given connection.
///
/// Returns a `HashMap<rowid, username>` for resolving session_id and sender_id.
pub fn load_name2id(conn: &Connection) -> Result<HashMap<i64, String>, DbError> {
    let mut stmt = conn.prepare("SELECT rowid, username FROM name2id")?;
    let mut map = HashMap::new();
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let rowid: i64 = row.get(0)?;
        let username: String = row.get(1)?;
        map.insert(rowid, username);
    }
    Ok(map)
}

// ---------------------------------------------------------------------------
// Message FTS search
// ---------------------------------------------------------------------------

/// Search the native WeChat message FTS database across all 4 shards.
///
/// `conn` must already have `MMFtsTokenizer` registered (via `open_fts_connection`).
///
/// Column layout (named columns in message_fts.db):
/// - acontent        (the text that was indexed)
/// - message_local_id
/// - sort_seq        (milliseconds)
/// - local_type      (encodes msg_type + sub_type)
/// - session_id      (rowid into name2id → talker wxid)
/// - sender_id       (rowid into name2id → sender wxid)
/// - create_time     (Unix seconds)
pub fn search_message_fts(
    conn: &Connection,
    keyword: &str,
    limit: usize,
    offset: usize,
) -> Result<NativeFtsResult, DbError> {
    search_message_fts_with_cache(conn, keyword, limit, offset, None)
}

/// Search the native WeChat message FTS database with an optional pre-loaded name2id cache.
///
/// When `name2id_cache` is `Some`, it is used directly instead of querying the database.
/// This avoids re-loading the name2id table on every search when the caller already has it.
pub fn search_message_fts_with_cache(
    conn: &Connection,
    keyword: &str,
    limit: usize,
    offset: usize,
    name2id_cache: Option<&HashMap<i64, String>>,
) -> Result<NativeFtsResult, DbError> {
    let fts_query = build_fts_query(keyword);
    if fts_query.is_empty() {
        return Ok(NativeFtsResult {
            hits: Vec::new(),
            total_hits: 0,
        });
    }

    // Use the provided cache or load from the database.
    let owned_name2id;
    let name2id: &HashMap<i64, String> = match name2id_cache {
        Some(cache) => cache,
        None => {
            owned_name2id = load_name2id(conn)?;
            &owned_name2id
        }
    };

    // Build UNION ALL across all 4 shards (using real column names from message_fts.db)
    let union_sql = "
        SELECT acontent, message_local_id, sort_seq, local_type, session_id, sender_id, create_time
            FROM message_fts_v4_0 WHERE message_fts_v4_0 MATCH ?1
        UNION ALL
        SELECT acontent, message_local_id, sort_seq, local_type, session_id, sender_id, create_time
            FROM message_fts_v4_1 WHERE message_fts_v4_1 MATCH ?1
        UNION ALL
        SELECT acontent, message_local_id, sort_seq, local_type, session_id, sender_id, create_time
            FROM message_fts_v4_2 WHERE message_fts_v4_2 MATCH ?1
        UNION ALL
        SELECT acontent, message_local_id, sort_seq, local_type, session_id, sender_id, create_time
            FROM message_fts_v4_3 WHERE message_fts_v4_3 MATCH ?1
        ORDER BY create_time DESC, sort_seq DESC, message_local_id DESC
        LIMIT ?2 OFFSET ?3
    ";

    let count_sql = "
        SELECT count(*) FROM (
            SELECT 1 FROM message_fts_v4_0 WHERE message_fts_v4_0 MATCH ?1
            UNION ALL
            SELECT 1 FROM message_fts_v4_1 WHERE message_fts_v4_1 MATCH ?1
            UNION ALL
            SELECT 1 FROM message_fts_v4_2 WHERE message_fts_v4_2 MATCH ?1
            UNION ALL
            SELECT 1 FROM message_fts_v4_3 WHERE message_fts_v4_3 MATCH ?1
        )
    ";

    // Count total matches
    let total_hits: usize = conn.query_row(count_sql, rusqlite::params![fts_query], |row| {
        row.get::<_, i64>(0)
    })? as usize;

    // Fetch paginated results
    let mut stmt = conn.prepare(union_sql)?;

    let rows: Vec<(String, i64, i64, i64, i64, i64, i64)> = stmt
        .query_map(
            rusqlite::params![fts_query, limit as i64, offset as i64],
            |row| {
                Ok((
                    row.get::<_, String>(0)?, // acontent
                    row.get::<_, i64>(1)?,    // message_local_id
                    row.get::<_, i64>(2)?,    // sort_seq
                    row.get::<_, i64>(3)?,    // local_type
                    row.get::<_, i64>(4)?,    // session_id
                    row.get::<_, i64>(5)?,    // sender_id
                    row.get::<_, i64>(6)?,    // create_time
                ))
            },
        )?
        .collect::<Result<Vec<_>, _>>()?;

    let hits: Vec<NativeFtsHit> = rows
        .into_iter()
        .map(
            |(
                snippet,
                message_local_id,
                sort_seq,
                local_type,
                session_id,
                sender_id,
                create_time,
            )| {
                let (msg_type, sub_type) = split_local_type(local_type);
                let talker = name2id
                    .get(&session_id)
                    .cloned()
                    .unwrap_or_else(|| format!("unknown:{session_id}"));
                let sender = name2id
                    .get(&sender_id)
                    .cloned()
                    .unwrap_or_else(|| format!("unknown:{sender_id}"));
                NativeFtsHit {
                    hit_type: FtsHitType::Message,
                    talker,
                    sender,
                    snippet,
                    create_time,
                    sort_seq,
                    message_local_id,
                    msg_type,
                    sub_type,
                    server_id: 0,
                }
            },
        )
        .collect();

    Ok(NativeFtsResult { hits, total_hits })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn open_fts_test_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        // Register the MMFtsTokenizer
        // We need to call register_mm_fts_tokenizer from wx_context, but since
        // wx-db doesn't depend on wx-context, we use the unicode61 tokenizer
        // for unit tests here. The integration test in wx-cli uses the real tokenizer.
        // Use real column names matching message_fts.db schema
        conn.execute_batch(
            "CREATE VIRTUAL TABLE message_fts_v4_0 USING fts5(acontent, message_local_id UNINDEXED, sort_seq UNINDEXED, local_type UNINDEXED, session_id UNINDEXED, sender_id UNINDEXED, create_time UNINDEXED, tokenize='unicode61');
             CREATE VIRTUAL TABLE message_fts_v4_1 USING fts5(acontent, message_local_id UNINDEXED, sort_seq UNINDEXED, local_type UNINDEXED, session_id UNINDEXED, sender_id UNINDEXED, create_time UNINDEXED, tokenize='unicode61');
             CREATE VIRTUAL TABLE message_fts_v4_2 USING fts5(acontent, message_local_id UNINDEXED, sort_seq UNINDEXED, local_type UNINDEXED, session_id UNINDEXED, sender_id UNINDEXED, create_time UNINDEXED, tokenize='unicode61');
             CREATE VIRTUAL TABLE message_fts_v4_3 USING fts5(acontent, message_local_id UNINDEXED, sort_seq UNINDEXED, local_type UNINDEXED, session_id UNINDEXED, sender_id UNINDEXED, create_time UNINDEXED, tokenize='unicode61');
             CREATE TABLE name2id (rowid INTEGER PRIMARY KEY, username TEXT NOT NULL);",
        )
        .unwrap();
        conn
    }

    #[allow(clippy::too_many_arguments)]
    fn insert_row(
        conn: &Connection,
        shard: usize,
        content: &str,
        message_local_id: i64,
        sort_seq: i64,
        local_type: i64,
        session_id: i64,
        sender_id: i64,
        create_time: i64,
    ) {
        let table = format!("message_fts_v4_{shard}");
        conn.execute(
            &format!(
                "INSERT INTO {table}(acontent,message_local_id,sort_seq,local_type,session_id,sender_id,create_time) VALUES(?1,?2,?3,?4,?5,?6,?7)"
            ),
            rusqlite::params![content, message_local_id, sort_seq, local_type, session_id, sender_id, create_time],
        )
        .unwrap();
    }

    // Test 1: load_name2id correctly builds the HashMap using real schema (username column)
    #[test]
    fn load_name2id_basic() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE name2id (rowid INTEGER PRIMARY KEY, username TEXT);
             INSERT INTO name2id VALUES (1, 'wxid_alice');
             INSERT INTO name2id VALUES (2, 'wxid_bob');",
        )
        .unwrap();
        let map = load_name2id(&conn).unwrap();
        assert_eq!(map.get(&1), Some(&"wxid_alice".to_string()));
        assert_eq!(map.get(&2), Some(&"wxid_bob".to_string()));
        assert_eq!(map.len(), 2);
    }

    // Test: load_name2id fails with wrong column name (regression guard for BUG-3)
    #[test]
    fn load_name2id_wrong_column_fails() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE name2id (rowid INTEGER PRIMARY KEY, user_name TEXT);
             INSERT INTO name2id VALUES (1, 'wxid_alice');",
        )
        .unwrap();
        assert!(
            load_name2id(&conn).is_err(),
            "load_name2id should fail when name2id has user_name column instead of username"
        );
    }

    // Test 2: Integration: messages in multiple shards, verify merge + ordering
    #[test]
    fn search_across_shards() {
        let conn = open_fts_test_db();
        // Add name2id entries
        conn.execute_batch(
            "INSERT INTO name2id VALUES (1, 'wxid_alice');
             INSERT INTO name2id VALUES (2, 'wxid_self');",
        )
        .unwrap();

        // Insert rows in different shards
        insert_row(
            &conn,
            0,
            "hello world from shard 0",
            1,
            1000,
            1,
            1,
            2,
            1700000001,
        );
        insert_row(
            &conn,
            1,
            "hello again from shard 1",
            2,
            2000,
            1,
            1,
            2,
            1700000002,
        );
        insert_row(&conn, 2, "goodbye shard 2", 3, 3000, 1, 1, 2, 1700000003);
        insert_row(
            &conn,
            3,
            "hello final shard 3",
            4,
            4000,
            1,
            1,
            2,
            1700000004,
        );

        let result = search_message_fts(&conn, "hello", 10, 0).unwrap();
        assert_eq!(result.total_hits, 3, "should find 3 hello messages");
        assert_eq!(result.hits.len(), 3);
        // Ordered by create_time DESC
        assert!(result.hits[0].create_time >= result.hits[1].create_time);
        assert!(result.hits[1].create_time >= result.hits[2].create_time);
    }

    // Test 3: Empty keyword returns empty results
    #[test]
    fn empty_keyword() {
        let conn = open_fts_test_db();
        let result = search_message_fts(&conn, "", 10, 0).unwrap();
        assert_eq!(result.total_hits, 0);
        assert!(result.hits.is_empty());
    }

    // Test 4: No matches returns 0 hits
    #[test]
    fn no_matches() {
        let conn = open_fts_test_db();
        conn.execute_batch("INSERT INTO name2id VALUES (1, 'wxid_alice');")
            .unwrap();
        insert_row(&conn, 0, "hello world", 1, 1000, 1, 1, 1, 1700000001);

        let result = search_message_fts(&conn, "nonexistent", 10, 0).unwrap();
        assert_eq!(result.total_hits, 0);
        assert!(result.hits.is_empty());
    }

    // Test 5: Pagination: limit/offset work correctly
    #[test]
    fn pagination() {
        let conn = open_fts_test_db();
        conn.execute_batch("INSERT INTO name2id VALUES (1, 'wxid_alice');")
            .unwrap();

        for i in 0..5usize {
            insert_row(
                &conn,
                i % 4,
                "hello message",
                i as i64 + 1, // message_local_id (distinct)
                (i as i64) * 100,
                1,
                1,
                1,
                1700000000 + i as i64,
            );
        }

        // All 5
        let all = search_message_fts(&conn, "hello", 10, 0).unwrap();
        assert_eq!(all.total_hits, 5);
        assert_eq!(all.hits.len(), 5);

        // First 2
        let page1 = search_message_fts(&conn, "hello", 2, 0).unwrap();
        assert_eq!(page1.total_hits, 5);
        assert_eq!(page1.hits.len(), 2);

        // Offset 3, limit 10 → 2 remaining
        let page2 = search_message_fts(&conn, "hello", 10, 3).unwrap();
        assert_eq!(page2.total_hits, 5);
        assert_eq!(page2.hits.len(), 2);
    }

    // name2id resolution
    #[test]
    fn name2id_resolution() {
        let conn = open_fts_test_db();
        conn.execute_batch(
            "INSERT INTO name2id VALUES (10, 'wxid_alice');
             INSERT INTO name2id VALUES (20, 'wxid_bob');",
        )
        .unwrap();
        insert_row(&conn, 0, "hello", 1, 1000, 1, 10, 20, 1700000001);

        let result = search_message_fts(&conn, "hello", 10, 0).unwrap();
        assert_eq!(result.hits.len(), 1);
        assert_eq!(result.hits[0].talker, "wxid_alice");
        assert_eq!(result.hits[0].sender, "wxid_bob");
        assert_eq!(result.hits[0].server_id, 0);
        assert_eq!(result.hits[0].message_local_id, 1);
    }

    // Test: pagination is stable even when (create_time, sort_seq) ties exist
    // Rows with same (c6, c2) but distinct c1 must not appear in both pages.
    #[test]
    fn pagination_stable_with_same_sort_key() {
        let conn = open_fts_test_db();
        conn.execute_batch("INSERT INTO name2id VALUES (1, 'wxid_alice');")
            .unwrap();

        // Insert 6 rows all with the same (create_time=1700000000, sort_seq=1000)
        // but distinct message_local_id (c1) to verify tie-breaker works.
        for mid in 1i64..=6 {
            insert_row(
                &conn,
                ((mid - 1) % 4) as usize,
                "same key message",
                mid,  // message_local_id (distinct tie-breaker)
                1000, // sort_seq (same for all)
                1,
                1,
                1,
                1700000000, // create_time (same for all)
            );
        }

        let page1 = search_message_fts(&conn, "same", 3, 0).unwrap();
        let page2 = search_message_fts(&conn, "same", 3, 3).unwrap();

        assert_eq!(page1.total_hits, 6);
        assert_eq!(page1.hits.len(), 3);
        assert_eq!(page2.total_hits, 6);
        assert_eq!(page2.hits.len(), 3);

        // No overlap: message_local_ids in page1 and page2 must be disjoint
        let ids1: std::collections::HashSet<i64> =
            page1.hits.iter().map(|h| h.message_local_id).collect();
        let ids2: std::collections::HashSet<i64> =
            page2.hits.iter().map(|h| h.message_local_id).collect();
        assert!(
            ids1.is_disjoint(&ids2),
            "Pagination overlap detected! page1={ids1:?}, page2={ids2:?}"
        );
    }
}
