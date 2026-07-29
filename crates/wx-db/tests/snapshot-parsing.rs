use std::path::Path;

use rusqlite::types::ValueRef;
use rusqlite::Connection;
use wx_db::{decode_message_for_test, Message};

struct FixtureResult {
    messages: Vec<Message>,
    skipped: usize,
    total: usize,
}

fn load_fixture(fixture_name: &str) -> FixtureResult {
    let fixture_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(fixture_name);
    let sql = std::fs::read_to_string(&fixture_path)
        .unwrap_or_else(|e| panic!("failed to read fixture {}: {}", fixture_path.display(), e));

    let conn = Connection::open_in_memory().expect("failed to open in-memory db");

    conn.execute_batch(
        "CREATE TABLE fixture_messages (
            sort_seq INTEGER NOT NULL,
            server_id INTEGER NOT NULL,
            local_type INTEGER NOT NULL,
            sender TEXT NOT NULL DEFAULT '',
            talker TEXT NOT NULL,
            create_time INTEGER NOT NULL DEFAULT 1700000000,
            message_content BLOB NOT NULL,
            packed_info_data BLOB,
            status INTEGER NOT NULL DEFAULT 0,
            wcdb_ct INTEGER,
            compress_content BLOB,
            is_group INTEGER NOT NULL DEFAULT 0
        );",
    )
    .expect("failed to create fixture_messages table");

    if !sql.trim().is_empty() {
        conn.execute_batch(&sql)
            .unwrap_or_else(|e| panic!("failed to execute fixture SQL {}: {}", fixture_name, e));
    }

    let mut stmt = conn
        .prepare(
            "SELECT sort_seq, server_id, local_type, sender, talker,
                    create_time, message_content, packed_info_data,
                    status, wcdb_ct, compress_content, is_group
             FROM fixture_messages ORDER BY sort_seq",
        )
        .expect("failed to prepare SELECT");

    let mut messages = Vec::new();
    let mut skipped = 0usize;
    let mut total = 0usize;

    let mut rows = stmt.query([]).expect("failed to query fixture_messages");
    while let Some(row) = rows.next().expect("failed to advance row") {
        total += 1;

        let sort_seq: i64 = row.get(0).unwrap();
        let server_id: i64 = row.get(1).unwrap();
        let local_type: i64 = row.get(2).unwrap();
        let sender: String = row.get(3).unwrap();
        let talker: String = row.get(4).unwrap();
        let create_time: i64 = row.get(5).unwrap();

        // message_content can be Text or Blob (mirrors production decode_message_row)
        let raw_content: Vec<u8> = match row.get_ref(6).unwrap() {
            ValueRef::Blob(b) => b.to_vec(),
            ValueRef::Text(b) => b.to_vec(),
            other => panic!("unexpected message_content type: {:?}", other),
        };

        let packed_info_data: Option<Vec<u8>> = row.get(7).unwrap();
        let status: i32 = row.get(8).unwrap();
        let wcdb_ct: Option<i32> = row.get(9).unwrap();
        let compress_content: Option<Vec<u8>> = row.get(10).unwrap();
        let is_group: bool = row.get(11).unwrap();

        match decode_message_for_test(
            sort_seq,
            server_id,
            local_type,
            &sender,
            &talker,
            create_time,
            &raw_content,
            packed_info_data.as_deref(),
            status,
            wcdb_ct,
            compress_content.as_deref(),
            is_group,
        ) {
            Ok(msg) => messages.push(msg),
            Err(e) => {
                eprintln!("decode error in fixture at sort_seq={}: {}", sort_seq, e);
                skipped += 1;
            }
        }
    }

    FixtureResult {
        messages,
        skipped,
        total,
    }
}

fn assert_no_message_loss(result: &FixtureResult) {
    assert_eq!(
        result.messages.len() + result.skipped,
        result.total,
        "invariant: parsed + skipped == total rows"
    );
}

#[test]
fn loader_handles_empty_fixture() {
    let result = load_fixture("empty.sql");
    assert_eq!(result.total, 0);
    assert_eq!(result.messages.len(), 0);
}

#[test]
fn snapshot_u64_local_type() {
    let result = load_fixture("01-u64-local-type.sql");
    assert_no_message_loss(&result);
    assert_eq!(result.skipped, 0, "no rows should be skipped");
    insta::assert_yaml_snapshot!(result.messages);
}

#[test]
fn snapshot_xml_null_sentinel() {
    let result = load_fixture("02-xml-null-sentinel.sql");
    assert_no_message_loss(&result);
    assert_eq!(result.skipped, 0, "no rows should be skipped");
    insta::assert_yaml_snapshot!(result.messages);
}

#[test]
fn snapshot_nested_quote_xml() {
    let result = load_fixture("03-nested-quote-xml.sql");
    assert_no_message_loss(&result);
    assert_eq!(result.skipped, 0, "no rows should be skipped");
    insta::assert_yaml_snapshot!(result.messages);
}

#[test]
fn snapshot_empty_title_channel() {
    let result = load_fixture("04-empty-title-channel.sql");
    assert_no_message_loss(&result);
    assert_eq!(result.skipped, 0, "no rows should be skipped");
    insta::assert_yaml_snapshot!(result.messages);
}

#[test]
fn snapshot_zstd_compressed() {
    let result = load_fixture("05-zstd-compressed.sql");
    assert_no_message_loss(&result);
    assert_eq!(result.skipped, 0, "no rows should be skipped");
    insta::assert_yaml_snapshot!(result.messages);
}

#[test]
fn snapshot_group_sender_parsing() {
    let result = load_fixture("06-group-sender-parsing.sql");
    assert_no_message_loss(&result);
    assert_eq!(result.skipped, 0, "no rows should be skipped");
    insta::assert_yaml_snapshot!(result.messages);
}

#[test]
fn snapshot_group_quote_chatusr() {
    let result = load_fixture("07-group-quote-chatusr.sql");
    assert_no_message_loss(&result);
    assert_eq!(result.skipped, 0, "no rows should be skipped");
    insta::assert_yaml_snapshot!(result.messages);
}

#[test]
fn snapshot_system_revokemsg() {
    let result = load_fixture("08-system-revokemsg.sql");
    assert_no_message_loss(&result);
    assert_eq!(result.skipped, 0, "no rows should be skipped");
    insta::assert_yaml_snapshot!(result.messages);
}
