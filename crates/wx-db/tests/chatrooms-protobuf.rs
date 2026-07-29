use std::fs;
use std::path::Path;

use rusqlite::{params, Connection};
use tempfile::TempDir;
use wx_db::test_ddl;
use wx_db::{encode_room_data_for_test, ChatRoomQuery, WechatDb};

// ---- helpers ----

/// Create a minimal fixture directory with contact.db (including chat_room table),
/// session.db, and message_0.db.
fn create_fixture() -> TempDir {
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

    // message/message_0.db (open needs at least 1 shard)
    let msg_dir = base.join("message");
    fs::create_dir_all(&msg_dir).unwrap();
    create_message_shard(&msg_dir.join("message_0.db"), 1000);

    dir
}

fn create_contact_db(path: &Path) {
    let conn = Connection::open(path).unwrap();

    // contact table (required by WechatDb)
    test_ddl::create_test_contact_table(&conn);

    // chat_room table
    conn.execute_batch(
        "CREATE TABLE chat_room (
            username TEXT,
            owner TEXT DEFAULT '',
            ext_buffer BLOB
        );",
    )
    .unwrap();

    // Row 1: valid protobuf with 2 members (one with display_name, one without)
    let ext_buffer =
        encode_room_data_for_test(&[("wxid_member1", Some("Member One")), ("wxid_member2", None)]);
    conn.execute(
        "INSERT INTO chat_room (username, owner, ext_buffer) VALUES (?1, ?2, ?3)",
        params!["group@chatroom", "wxid_member1", ext_buffer],
    )
    .unwrap();

    // Row 2: empty ext_buffer (should return empty members, not panic)
    conn.execute(
        "INSERT INTO chat_room (username, owner, ext_buffer) VALUES (?1, ?2, ?3)",
        params!["empty_group@chatroom", "wxid_owner", Vec::<u8>::new()],
    )
    .unwrap();

    // Row 3: another group for testing list-all
    let ext_buffer2 = encode_room_data_for_test(&[("wxid_solo", Some("Solo Name"))]);
    conn.execute(
        "INSERT INTO chat_room (username, owner, ext_buffer) VALUES (?1, ?2, ?3)",
        params!["another_group@chatroom", "wxid_solo", ext_buffer2],
    )
    .unwrap();
}

fn create_session_db(path: &Path) {
    let conn = Connection::open(path).unwrap();
    test_ddl::create_test_session_table(&conn);
}

fn create_message_shard(path: &Path, timestamp: i64) {
    let conn = Connection::open(path).unwrap();
    conn.execute_batch("CREATE TABLE Timestamp (timestamp INTEGER);")
        .unwrap();
    conn.execute("INSERT INTO Timestamp VALUES (?1)", params![timestamp])
        .unwrap();
}

// ---- tests ----

#[test]
fn chatrooms_protobuf_query_by_username() {
    let dir = create_fixture();
    let db = WechatDb::open(dir.path()).unwrap();

    let result = db
        .query_chatrooms(&ChatRoomQuery::new().username("group@chatroom"))
        .unwrap();

    assert_eq!(result.items.len(), 1);
    assert_eq!(result.stats.skipped, 0);

    let room = &result.items[0];
    assert_eq!(room.username, "group@chatroom");
    assert_eq!(room.owner, "wxid_member1");
    assert_eq!(room.members.len(), 2);

    // First member: has display_name
    assert_eq!(room.members[0].user_name, "wxid_member1");
    assert_eq!(room.members[0].display_name.as_deref(), Some("Member One"));

    // Second member: no display_name
    assert_eq!(room.members[1].user_name, "wxid_member2");
    assert_eq!(room.members[1].display_name, None);
}

#[test]
fn chatrooms_protobuf_empty_ext_buffer() {
    let dir = create_fixture();
    let db = WechatDb::open(dir.path()).unwrap();

    let result = db
        .query_chatrooms(&ChatRoomQuery::new().username("empty_group@chatroom"))
        .unwrap();

    assert_eq!(result.items.len(), 1);
    assert_eq!(result.stats.skipped, 0); // empty ext_buffer is normal, not skipped

    let room = &result.items[0];
    assert_eq!(room.username, "empty_group@chatroom");
    assert_eq!(room.owner, "wxid_owner");
    assert!(room.members.is_empty());
}

#[test]
fn chatrooms_protobuf_query_all() {
    let dir = create_fixture();
    let db = WechatDb::open(dir.path()).unwrap();

    let result = db.query_chatrooms(&ChatRoomQuery::new()).unwrap();

    assert_eq!(result.stats.total_rows, 3);
    assert_eq!(result.items.len(), 3);
    assert_eq!(result.stats.skipped, 0);
}

#[test]
fn chatrooms_protobuf_query_nonexistent_username() {
    let dir = create_fixture();
    let db = WechatDb::open(dir.path()).unwrap();

    let result = db
        .query_chatrooms(&ChatRoomQuery::new().username("nonexistent@chatroom"))
        .unwrap();

    assert_eq!(result.items.len(), 0);
    assert_eq!(result.stats.total_rows, 0);
}

#[test]
fn chatrooms_protobuf_query_with_limit() {
    let dir = create_fixture();
    let db = WechatDb::open(dir.path()).unwrap();

    let result = db.query_chatrooms(&ChatRoomQuery::new().limit(1)).unwrap();

    assert_eq!(result.items.len(), 1);
    assert_eq!(result.stats.total_rows, 3); // total_rows = pre-limit count
}

#[test]
fn chatrooms_protobuf_query_with_offset() {
    let dir = create_fixture();
    let db = WechatDb::open(dir.path()).unwrap();

    let result = db
        .query_chatrooms(&ChatRoomQuery::new().limit(100).offset(2))
        .unwrap();

    assert_eq!(result.items.len(), 1); // 3 total, offset 2 = 1 remaining
    assert_eq!(result.stats.total_rows, 3); // total_rows = pre-limit count
}

#[test]
fn chatrooms_protobuf_pagination_stability() {
    let dir = create_fixture();
    let db = WechatDb::open(dir.path()).unwrap();

    // Page 1: offset=0, limit=2
    let page1 = db
        .query_chatrooms(&ChatRoomQuery::new().limit(2).offset(0))
        .unwrap();
    // Page 2: offset=2, limit=2
    let page2 = db
        .query_chatrooms(&ChatRoomQuery::new().limit(2).offset(2))
        .unwrap();

    assert_eq!(page1.items.len(), 2);
    assert_eq!(page2.items.len(), 1);

    // Ensure no overlap
    let page1_names: Vec<&str> = page1.items.iter().map(|r| r.username.as_str()).collect();
    let page2_names: Vec<&str> = page2.items.iter().map(|r| r.username.as_str()).collect();
    for name in &page2_names {
        assert!(
            !page1_names.contains(name),
            "chatroom {name} appears in both pages"
        );
    }
}
