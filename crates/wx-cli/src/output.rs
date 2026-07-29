use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JsonEnvelope<T> {
    pub items: Vec<T>,
    pub paging: PagingMeta,
    pub stats: StatsMeta,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PagingMeta {
    pub limit: usize,
    pub offset: usize,
    pub returned: usize,
    pub has_more: bool,
    pub total: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StatsMeta {
    pub scanned: usize,
    pub skipped: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub elapsed_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub shard_warnings: Vec<wx_db::ShardWarning>,
}

impl<T> JsonEnvelope<T> {
    pub fn from_query_result<U>(
        result: wx_db::QueryResult<U>,
        limit: usize,
        offset: usize,
        map_item: impl FnMut(U) -> T,
    ) -> Self {
        let returned = result.items.len();
        // total: use filtered_count if available (messages), otherwise total_rows
        let total = result
            .stats
            .filtered_count
            .unwrap_or(result.stats.total_rows);
        let has_more = offset + returned < total;
        Self {
            items: result.items.into_iter().map(map_item).collect(),
            paging: PagingMeta {
                limit,
                offset,
                returned,
                has_more,
                total,
            },
            stats: StatsMeta {
                scanned: result.stats.total_rows,
                skipped: result.stats.skipped,
                elapsed_ms: None,
                shard_warnings: Vec::new(),
            },
        }
    }

    pub fn from_message_query_result(
        result: wx_db::MessageQueryResult,
        limit: usize,
        offset: usize,
        map_item: impl FnMut(wx_db::Message) -> T,
    ) -> Self {
        let returned = result.items.len();
        let total = result
            .stats
            .filtered_count
            .unwrap_or(result.stats.total_rows);
        let has_more = offset + returned < total;
        let shard_warnings = result.shard_warnings;
        Self {
            items: result.items.into_iter().map(map_item).collect(),
            paging: PagingMeta {
                limit,
                offset,
                returned,
                has_more,
                total,
            },
            stats: StatsMeta {
                scanned: result.stats.total_rows,
                skipped: result.stats.skipped,
                elapsed_ms: None,
                shard_warnings,
            },
        }
    }

    /// Kept for Task 6: remove self-built FTS index code.
    #[allow(dead_code)]
    pub fn from_fts_result<U>(
        items: Vec<U>,
        total: usize,
        limit: usize,
        offset: usize,
        map_item: impl FnMut(U) -> T,
    ) -> Self {
        let returned = items.len();
        let has_more = offset + returned < total;
        Self {
            items: items.into_iter().map(map_item).collect(),
            paging: PagingMeta {
                limit,
                offset,
                returned,
                has_more,
                total,
            },
            stats: StatsMeta {
                scanned: total,
                skipped: 0,
                elapsed_ms: None,
                shard_warnings: Vec::new(),
            },
        }
    }
}
