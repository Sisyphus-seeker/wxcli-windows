use std::fs;
use std::path::Path;

use rusqlite::{params, Connection};
use tempfile::TempDir;
use wx_db::test_ddl;
use wx_db::{encode_extra_buffer_for_test, ContactQuery, WechatDb};

// ---- helpers ----

/// Create a fixture with contacts that have extra_buffer data, description, and labels.
fn create_fixture_extended() -> TempDir {
    let dir = TempDir::new().unwrap();
    let base = dir.path();

    // contact/contact.db
    let contact_dir = base.join("contact");
    fs::create_dir_all(&contact_dir).unwrap();
    create_contact_db_extended(&contact_dir.join("contact.db"));

    // session/session.db (minimal)
    let session_dir = base.join("session");
    fs::create_dir_all(&session_dir).unwrap();
    create_session_db(&session_dir.join("session.db"));

    // message/message_0.db (minimal shard)
    let msg_dir = base.join("message");
    fs::create_dir_all(&msg_dir).unwrap();
    create_message_shard(&msg_dir.join("message_0.db"), 1000);

    dir
}

/// Create a fixture WITHOUT a contact_label table.
fn create_fixture_no_label_table() -> TempDir {
    let dir = TempDir::new().unwrap();
    let base = dir.path();

    let contact_dir = base.join("contact");
    fs::create_dir_all(&contact_dir).unwrap();
    {
        let conn = Connection::open(contact_dir.join("contact.db")).unwrap();
        test_ddl::create_test_contact_table(&conn);
        // No contact_label table at all
        let blob =
            encode_extra_buffer_for_test(Some(1), None, None, None, None, None, None, Some("5,6"));
        conn.execute(
            "INSERT INTO contact (username, alias, remark, nick_name, extra_buffer) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params!["wxid_nolabel", "", "No Label", "", blob],
        )
        .unwrap();
    }

    let session_dir = base.join("session");
    fs::create_dir_all(&session_dir).unwrap();
    create_session_db(&session_dir.join("session.db"));

    let msg_dir = base.join("message");
    fs::create_dir_all(&msg_dir).unwrap();
    create_message_shard(&msg_dir.join("message_0.db"), 1000);

    dir
}

fn create_contact_db_extended(path: &Path) {
    let conn = Connection::open(path).unwrap();
    test_ddl::create_test_contact_table(&conn);
    test_ddl::create_test_contact_label_table(&conn);

    // Label rows
    conn.execute(
        "INSERT INTO contact_label VALUES (?1, ?2, ?3)",
        params!["5", "体育生", 0],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO contact_label VALUES (?1, ?2, ?3)",
        params!["6", "直男", 1],
    )
    .unwrap();

    // Contact 1: all fields populated
    let blob_full = encode_extra_buffer_for_test(
        Some(1),
        Some("成长本就是一个孤立无援的过程"),
        Some("CN"),
        Some("Beijing"),
        Some("Haidian"),
        Some(30),
        Some("15891926830"),
        Some("5,6"),
    );
    conn.execute(
        "INSERT INTO contact (username, alias, remark, nick_name, description, extra_buffer) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            "wxid_full",
            "Dalong-SS",
            "张三",
            "大龙",
            "QQ 442007516",
            blob_full
        ],
    )
    .unwrap();

    // Contact 2: empty extra_buffer
    conn.execute(
        "INSERT INTO contact (username, alias, remark, nick_name) \
         VALUES (?1, ?2, ?3, ?4)",
        params!["wxid_empty", "empty_alias", "Empty Remark", "Empty Nick"],
    )
    .unwrap();

    // Contact 3: partial region (only province)
    let blob_partial =
        encode_extra_buffer_for_test(None, None, None, Some("Guangdong"), None, None, None, None);
    conn.execute(
        "INSERT INTO contact (username, alias, remark, nick_name, extra_buffer) \
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            "wxid_partial",
            "",
            "Partial Remark",
            "Partial",
            blob_partial
        ],
    )
    .unwrap();

    // Contact 4: phone only (for keyword search test)
    let blob_phone = encode_extra_buffer_for_test(
        None,
        None,
        None,
        None,
        None,
        None,
        Some("13912345678"),
        None,
    );
    conn.execute(
        "INSERT INTO contact (username, alias, remark, nick_name, extra_buffer) \
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params!["wxid_phone", "", "Phone Guy", "PG", blob_phone],
    )
    .unwrap();
}

fn create_session_db(path: &Path) {
    let conn = Connection::open(path).unwrap();
    test_ddl::create_test_session_table_extended(&conn);
    conn.execute(
        "INSERT INTO SessionTable VALUES (?1, ?2, ?3, NULL, NULL, NULL)",
        params!["wxid_full", 1000, "hello"],
    )
    .unwrap();
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
fn contact_extra_buffer_all_fields() {
    let dir = create_fixture_extended();
    let db = WechatDb::open(dir.path()).unwrap();
    let result = db.query_contacts(&ContactQuery::new()).unwrap();

    let full = result
        .items
        .iter()
        .find(|c| c.user_name == "wxid_full")
        .unwrap();

    assert_eq!(full.gender, Some(1));
    assert_eq!(
        full.signature.as_deref(),
        Some("成长本就是一个孤立无援的过程")
    );
    assert_eq!(full.region.as_deref(), Some("CN · Beijing · Haidian"));
    assert_eq!(full.source_scene, Some(30));
    assert_eq!(full.phone.as_deref(), Some("15891926830"));
    assert_eq!(full.memo.as_deref(), Some("QQ 442007516"));
}

#[test]
fn contact_extra_buffer_phone_extraction() {
    let dir = create_fixture_extended();
    let db = WechatDb::open(dir.path()).unwrap();
    let result = db.query_contacts(&ContactQuery::new()).unwrap();

    let phone_guy = result
        .items
        .iter()
        .find(|c| c.user_name == "wxid_phone")
        .unwrap();
    assert_eq!(phone_guy.phone.as_deref(), Some("13912345678"));
}

#[test]
fn contact_extra_buffer_labels_resolved() {
    let dir = create_fixture_extended();
    let db = WechatDb::open(dir.path()).unwrap();
    let result = db.query_contacts(&ContactQuery::new()).unwrap();

    let full = result
        .items
        .iter()
        .find(|c| c.user_name == "wxid_full")
        .unwrap();
    assert_eq!(full.labels.len(), 2);
    assert!(full.labels.contains(&"体育生".to_string()));
    assert!(full.labels.contains(&"直男".to_string()));
}

#[test]
fn contact_extra_buffer_empty_blob() {
    let dir = create_fixture_extended();
    let db = WechatDb::open(dir.path()).unwrap();
    let result = db.query_contacts(&ContactQuery::new()).unwrap();

    let empty = result
        .items
        .iter()
        .find(|c| c.user_name == "wxid_empty")
        .unwrap();
    assert_eq!(empty.gender, None);
    assert_eq!(empty.signature, None);
    assert_eq!(empty.region, None);
    assert_eq!(empty.source_scene, None);
    assert_eq!(empty.phone, None);
    assert!(empty.labels.is_empty());
}

#[test]
fn contact_extra_buffer_no_label_table() {
    let dir = create_fixture_no_label_table();
    let db = WechatDb::open(dir.path()).unwrap();
    let result = db.query_contacts(&ContactQuery::new()).unwrap();

    let c = &result.items[0];
    assert_eq!(c.user_name, "wxid_nolabel");
    // label_ids are "5,6" but no contact_label table → labels is empty
    assert!(c.labels.is_empty());
    // gender still decoded
    assert_eq!(c.gender, Some(1));
}

#[test]
fn contact_extra_buffer_partial_region() {
    let dir = create_fixture_extended();
    let db = WechatDb::open(dir.path()).unwrap();
    let result = db.query_contacts(&ContactQuery::new()).unwrap();

    let partial = result
        .items
        .iter()
        .find(|c| c.user_name == "wxid_partial")
        .unwrap();
    assert_eq!(partial.region.as_deref(), Some("Guangdong"));
}

#[test]
fn contact_memo_from_description() {
    let dir = create_fixture_extended();
    let db = WechatDb::open(dir.path()).unwrap();
    let result = db.query_contacts(&ContactQuery::new()).unwrap();

    let full = result
        .items
        .iter()
        .find(|c| c.user_name == "wxid_full")
        .unwrap();
    assert_eq!(full.memo.as_deref(), Some("QQ 442007516"));

    // Contact with no description → memo is None
    let empty = result
        .items
        .iter()
        .find(|c| c.user_name == "wxid_empty")
        .unwrap();
    assert_eq!(empty.memo, None);
}

#[test]
fn contact_keyword_matches_description() {
    let dir = create_fixture_extended();
    let db = WechatDb::open(dir.path()).unwrap();

    let result = db
        .query_contacts(&ContactQuery::new().keyword("442007"))
        .unwrap();
    assert_eq!(result.items.len(), 1);
    assert_eq!(result.items[0].user_name, "wxid_full");
    assert_eq!(result.stats.filtered_count, Some(1));
}

#[test]
fn contact_keyword_matches_phone() {
    let dir = create_fixture_extended();
    let db = WechatDb::open(dir.path()).unwrap();

    let result = db
        .query_contacts(&ContactQuery::new().keyword("13912345"))
        .unwrap();
    assert_eq!(result.items.len(), 1);
    assert_eq!(result.items[0].user_name, "wxid_phone");
}

#[test]
fn contact_keyword_matches_label_name() {
    let dir = create_fixture_extended();
    let db = WechatDb::open(dir.path()).unwrap();

    let result = db
        .query_contacts(&ContactQuery::new().keyword("体育生"))
        .unwrap();
    assert_eq!(result.items.len(), 1);
    assert_eq!(result.items[0].user_name, "wxid_full");
}
