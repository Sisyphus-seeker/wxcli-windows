use crate::decode::decode_room_data;
use crate::error::DbError;
use crate::model::{effective_limit, ChatRoom, ChatRoomQuery, QueryResult, QueryStats};
use crate::open::WechatDb;

impl WechatDb {
    /// Query chatrooms, optionally filtered by username.
    pub fn query_chatrooms(&self, query: &ChatRoomQuery) -> Result<QueryResult<ChatRoom>, DbError> {
        let limit = effective_limit(query.limit);

        let (sql, params_vec) = if let Some(ref username) = query.username {
            (
                "SELECT username, owner, ext_buffer \
                 FROM chat_room \
                 WHERE username = ?1 \
                 ORDER BY username ASC \
                 LIMIT ?2 OFFSET ?3"
                    .to_string(),
                vec![
                    rusqlite::types::Value::Text(username.clone()),
                    rusqlite::types::Value::Integer(limit as i64),
                    rusqlite::types::Value::Integer(query.offset as i64),
                ],
            )
        } else {
            (
                "SELECT username, owner, ext_buffer \
                 FROM chat_room \
                 ORDER BY username ASC \
                 LIMIT ?1 OFFSET ?2"
                    .to_string(),
                vec![
                    rusqlite::types::Value::Integer(limit as i64),
                    rusqlite::types::Value::Integer(query.offset as i64),
                ],
            )
        };

        // Count total matching rows before LIMIT/OFFSET
        let count_sql = if query.username.is_some() {
            "SELECT COUNT(*) FROM chat_room WHERE username = ?1"
        } else {
            "SELECT COUNT(*) FROM chat_room"
        };
        let total_rows: usize = if let Some(ref username) = query.username {
            self.contact_conn
                .query_row(count_sql, [username.as_str()], |row| row.get::<_, i64>(0))?
                as usize
        } else {
            self.contact_conn
                .query_row(count_sql, [], |row| row.get::<_, i64>(0))? as usize
        };

        let mut stmt = self.contact_conn.prepare(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(params_vec.iter()), |row| {
            let username: String = row.get(0)?;
            let owner: String = row.get::<_, String>(1).unwrap_or_default();
            let ext_buffer: Vec<u8> = row.get::<_, Vec<u8>>(2).unwrap_or_default();
            Ok((username, owner, ext_buffer))
        })?;

        let mut items = Vec::new();

        for row_result in rows {
            let (username, owner, ext_buffer) = match row_result {
                Ok(r) => r,
                Err(_) => continue,
            };

            let members = if ext_buffer.is_empty() {
                Vec::new()
            } else {
                decode_room_data(&ext_buffer)
            };

            items.push(ChatRoom {
                username,
                owner,
                members,
            });
        }

        Ok(QueryResult {
            items,
            stats: QueryStats {
                total_rows,
                filtered_count: None,
                skipped: 0,
            },
        })
    }
}
