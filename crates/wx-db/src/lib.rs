//! Read-only query layer for local WeChat databases (decrypted or encrypted).
//!
//! This crate provides [`WechatDb`] — a handle to an opened WeChat database
//! directory — along with typed query structs for messages, contacts,
//! chatrooms, and sessions.
//!
//! Databases can be opened in two modes:
//! - **Decrypted**: via [`WechatDb::open`] on a pre-decrypted directory
//! - **Encrypted (direct)**: via [`WechatDb::open_encrypted`] using a raw key
//!   and SQLCipher's `sqlite3_key()` C API
//!
//! # Usage
//!
//! ```ignore
//! use wx_db::{WechatDb, MessageQuery, ContactQuery};
//!
//! // Open decrypted DB
//! let db = WechatDb::open("/path/to/decrypted/db")?;
//!
//! // Or open encrypted DB directly with raw key
//! let db = WechatDb::open_encrypted("/path/to/db_storage", raw_key)?;
//!
//! let messages = db.query_messages(&MessageQuery::for_talker("wxid_alice"))?;
//! let contacts = db.query_contacts(&ContactQuery::new())?;
//! ```

mod chatrooms;
mod contact_proto;
mod contacts;
mod decode;
mod error;
mod fts;
mod messages;
mod model;
pub mod native_fts;
mod open;
mod pool;
mod sessions;
pub mod shard_metadata;
mod xml_extract;

pub use error::{DbError, ShardWarning};
pub use fts::{FtsBuildStats, FtsHit, FtsSearchResult};
pub use model::*;
pub use native_fts::{load_name2id, FtsHitType, NativeFtsHit, NativeFtsResult};
pub use open::{open_readonly_connection, WechatDb};
pub use pool::ShardPool;
pub use xml_extract::extract_quote_fromusr;

// Test-only helpers for building protobuf fixtures.
#[doc(hidden)]
pub use contact_proto::encode_extra_buffer_for_test;
#[doc(hidden)]
pub use decode::decode_message_for_test;
#[doc(hidden)]
pub use decode::encode_packed_info_for_test;
#[doc(hidden)]
pub use decode::encode_room_data_for_test;

/// Shared test-fixture DDL helpers.
///
/// These functions create the standard table schemas used across integration
/// tests so that the DDL strings live in one place.  All helpers accept an
/// `&rusqlite::Connection` and execute the `CREATE TABLE` statement
/// directly.
#[doc(hidden)]
pub mod test_ddl {
    use rusqlite::Connection;

    /// Create the full `contact` table (7 columns) used by most integration tests.
    ///
    /// Schema: `username, alias, remark, nick_name, description, extra_buffer`.
    pub fn create_test_contact_table(conn: &Connection) {
        conn.execute_batch(
            "CREATE TABLE contact (
                username TEXT PRIMARY KEY,
                alias TEXT DEFAULT '',
                remark TEXT DEFAULT '',
                nick_name TEXT DEFAULT '',
                description TEXT DEFAULT NULL,
                extra_buffer BLOB DEFAULT NULL
            );",
        )
        .unwrap();
    }

    /// Create the minimal `contact` table (4 columns) used by simpler fixtures.
    ///
    /// Schema: `username, alias, remark, nick_name`.
    pub fn create_test_contact_table_minimal(conn: &Connection) {
        conn.execute_batch(
            "CREATE TABLE contact (
                username TEXT PRIMARY KEY,
                alias TEXT DEFAULT '',
                remark TEXT DEFAULT '',
                nick_name TEXT DEFAULT ''
            );",
        )
        .unwrap();
    }

    /// Create the `SessionTable` used by session and message query tests.
    ///
    /// Schema: `username, sort_timestamp, summary`.
    pub fn create_test_session_table(conn: &Connection) {
        conn.execute_batch(
            "CREATE TABLE SessionTable (
                username TEXT,
                sort_timestamp INTEGER,
                summary TEXT
            );",
        )
        .unwrap();
    }

    /// Create the `SessionTable` with extended columns used by session tests
    /// that need `last_msg_type`, `last_msg_sender`, and `last_sender_display_name`.
    ///
    /// Schema: `username, sort_timestamp, summary, last_msg_type, last_msg_sender,
    ///          last_sender_display_name`.
    pub fn create_test_session_table_extended(conn: &Connection) {
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

    /// Create the `contact_label` table used by label-aware tests.
    ///
    /// Schema: `label_id_, label_name_, sort_order_`.
    pub fn create_test_contact_label_table(conn: &Connection) {
        conn.execute_batch(
            "CREATE TABLE contact_label (
                label_id_ TEXT,
                label_name_ TEXT,
                sort_order_ INTEGER
            );",
        )
        .unwrap();
    }
}
