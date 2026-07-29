use rusqlite::types::ValueRef;

use crate::decode::decode_content;
use crate::error::DbError;
use crate::model::{effective_limit, QueryResult, QueryStats, Session, SessionQuery};
use crate::open::WechatDb;

/// Strip the `"wxid_xxx:\n"` sender prefix from group chat summaries.
///
/// Only strips when `username` ends with `@chatroom`. For non-group sessions,
/// the summary is returned unchanged.
fn strip_group_summary_prefix(username: &str, summary: String) -> String {
    if !crate::model::is_group_chat(username) {
        return summary;
    }
    if let Some(newline_pos) = summary.find('\n') {
        let prefix = &summary[..newline_pos];
        // Prefix should end with ':' and contain no spaces (looks like "wxid_xxx:")
        if prefix.ends_with(':') && !prefix.contains(' ') {
            return summary[newline_pos + 1..].to_string();
        }
    }
    summary
}

impl WechatDb {
    /// Query recent sessions (conversations).
    pub fn query_sessions(&self, query: &SessionQuery) -> Result<QueryResult<Session>, DbError> {
        let limit = effective_limit(query.limit);

        // Count total rows before LIMIT/OFFSET
        let total_rows: usize =
            self.session_conn
                .query_row("SELECT COUNT(*) FROM SessionTable", [], |row| {
                    row.get::<_, i64>(0)
                })? as usize;

        let sql = format!(
            "SELECT username, sort_timestamp, summary, \
                    last_msg_type, last_msg_sender, last_sender_display_name \
             FROM SessionTable \
             ORDER BY sort_timestamp {order}, username ASC \
             LIMIT ?1 OFFSET ?2",
            order = query.order.sql_keyword(),
        );

        let mut stmt = self.session_conn.prepare(&sql)?;
        let mut rows = stmt.query([limit as i64, query.offset as i64])?;

        let mut items = Vec::new();
        let mut skipped: usize = 0;

        while let Some(row) = rows.next()? {
            let username: String = row.get(0)?;
            let sort_timestamp: i64 = row.get(1)?;

            // summary can be Text or Blob (zstd-compressed)
            let summary = match row.get_ref(2)? {
                ValueRef::Text(bytes) => String::from_utf8_lossy(bytes).into_owned(),
                ValueRef::Blob(bytes) => match decode_content(bytes, None) {
                    Ok(s) => s,
                    Err(_) => {
                        skipped += 1;
                        continue;
                    }
                },
                ValueRef::Null => String::new(),
                _ => String::new(),
            };

            let last_msg_type = row.get::<_, Option<i64>>(3)?.map(|v| v as u32);
            let last_msg_sender: Option<String> = row.get(4)?;
            let last_sender_display_name: Option<String> = row.get(5)?;

            let summary = strip_group_summary_prefix(&username, summary);

            items.push(Session {
                username,
                summary,
                sort_timestamp,
                last_msg_type,
                last_msg_sender,
                last_sender_display_name,
            });
        }

        Ok(QueryResult {
            items,
            stats: QueryStats {
                total_rows,
                filtered_count: None,
                skipped,
            },
        })
    }
}
