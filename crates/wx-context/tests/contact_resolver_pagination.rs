use std::fs;

use rusqlite::{params, Connection};
use tempfile::TempDir;
use wx_context::ContactResolver;
use wx_db::WechatDb;

/// Create a fixture directory with 10,005 contacts to test pagination beyond the 10K boundary.
fn create_fixture_with_many_contacts(count: usize) -> TempDir {
    let dir = TempDir::new().unwrap();
    let base = dir.path();

    // contact/contact.db
    let contact_dir = base.join("contact");
    fs::create_dir_all(&contact_dir).unwrap();
    {
        let conn = Connection::open(contact_dir.join("contact.db")).unwrap();
        conn.execute_batch(
            "CREATE TABLE contact (
                username TEXT PRIMARY KEY,
                alias TEXT DEFAULT '',
                remark TEXT DEFAULT '',
                nick_name TEXT DEFAULT '',
                description TEXT DEFAULT NULL,
                extra_buffer BLOB DEFAULT NULL
            );
            CREATE TABLE contact_label (
                label_id_ TEXT,
                label_name_ TEXT,
                sort_order_ INTEGER
            );",
        )
        .unwrap();

        // Insert contacts in a transaction for speed
        conn.execute_batch("BEGIN").unwrap();
        for i in 0..count {
            conn.execute(
                "INSERT INTO contact (username, nick_name) VALUES (?1, ?2)",
                params![format!("wxid_{i:06}"), format!("User {i}")],
            )
            .unwrap();
        }
        conn.execute_batch("COMMIT").unwrap();
    }

    // session/session.db (required by WechatDb::open)
    let session_dir = base.join("session");
    fs::create_dir_all(&session_dir).unwrap();
    {
        let conn = Connection::open(session_dir.join("session.db")).unwrap();
        conn.execute_batch(
            "CREATE TABLE SessionTable (
                username TEXT,
                sort_timestamp INTEGER,
                summary TEXT,
                last_msg_type INTEGER,
                last_msg_sender TEXT,
                last_sender_display_name TEXT
            );",
        )
        .unwrap();
    }

    // message/ (empty dir — no shards needed for contact resolution)
    let msg_dir = base.join("message");
    fs::create_dir_all(&msg_dir).unwrap();

    dir
}

#[test]
fn contact_resolver_loads_all_contacts_beyond_10k() {
    let dir = create_fixture_with_many_contacts(10_005);
    let db = WechatDb::open(dir.path()).unwrap();
    let resolver = ContactResolver::build(&db).unwrap();

    // Contacts sorted by username: wxid_000000 .. wxid_010004
    // The last 5 (wxid_010000 .. wxid_010004) would be beyond the 10K cutoff without pagination
    for i in 10_000..10_005 {
        let wxid = format!("wxid_{i:06}");
        let expected = format!("User {i}");
        assert_eq!(
            resolver.display_name(&wxid),
            expected,
            "contact {wxid} should be resolvable (beyond 10K boundary)"
        );
    }

    // Also verify first contact is present
    assert_eq!(resolver.display_name("wxid_000000"), "User 0");
}
