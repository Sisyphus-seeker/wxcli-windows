//! Shard routing: determine which message shard IDs to decrypt based on
//! cached shard metadata and query time bounds.

use std::path::Path;

use wx_db::shard_metadata::{read_shard_metadata, write_shard_metadata, ShardMetadataFile};
use wx_db::WechatDb;

/// Determine which shard IDs to decrypt for a given query.
///
/// Returns `Some(shard_ids)` when routing can reduce the set of shards needed.
/// Returns `None` when routing is not possible or not beneficial (caller should
/// fall back to decrypting all shards).
///
/// Routing only activates when at least one of `since`/`until` is explicitly
/// provided. Without explicit time bounds, we cannot safely determine a subset.
pub fn route_shards_for_query(
    decrypted_root: &Path,
    talker: &str,
    since: Option<i64>,
    until: Option<i64>,
) -> Option<Vec<u32>> {
    // Only route when explicit time bounds are provided
    if since.is_none() && until.is_none() {
        return None;
    }

    // Read cached shard metadata
    let msg_dir = decrypted_root.join("message");
    let meta = read_shard_metadata(&msg_dir)?;

    // Staleness check: verify no shard DB has been modified after metadata was written
    if is_metadata_stale(&meta, &msg_dir) {
        return None;
    }

    // Look up talker's sort_timestamp from session.db for upper bound
    let session_path = decrypted_root.join("session").join("session.db");
    let sort_timestamp = read_sort_timestamp(&session_path, talker)?;

    // Compute effective time range
    let start = since.unwrap_or(0);
    let end = until.unwrap_or(sort_timestamp);

    // Filter shards overlapping [start, end]
    let filtered: Vec<u32> = meta
        .shards
        .iter()
        .filter(|s| s.start_unix <= end && s.end_unix >= start)
        .map(|s| s.shard_id)
        .collect();

    // No meaningful reduction → fall back
    if filtered.is_empty() || filtered.len() >= meta.shards.len() {
        return None;
    }

    Some(filtered)
}

/// Write the shard metadata sidecar from a `WechatDb` instance.
/// This keeps the write responsibility in wx-context, not in wx-db.
pub fn write_shard_metadata_sidecar(
    db: &WechatDb,
    decrypted_root: &Path,
) -> Result<(), std::io::Error> {
    let meta = db.shard_metadata();
    let msg_dir = decrypted_root.join("message");
    if msg_dir.is_dir() {
        write_shard_metadata(&msg_dir, &meta)?;
    }
    Ok(())
}

/// Check whether the metadata is stale by comparing shard DB mtimes.
fn is_metadata_stale(meta: &ShardMetadataFile, msg_dir: &Path) -> bool {
    for shard in &meta.shards {
        let db_path = msg_dir.join(format!("message_{}.db", shard.shard_id));
        if let Ok(file_meta) = std::fs::metadata(&db_path) {
            if let Ok(mtime) = file_meta.modified() {
                let mtime_nanos = mtime
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos();
                if mtime_nanos > meta.written_at_ns {
                    return true;
                }
            }
        }
        // If we can't read mtime, be conservative — don't mark stale
    }
    false
}

/// Read a talker's `sort_timestamp` from session.db.
fn read_sort_timestamp(session_path: &Path, talker: &str) -> Option<i64> {
    let conn = rusqlite::Connection::open_with_flags(
        session_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .ok()?;
    conn.query_row(
        "SELECT sort_timestamp FROM SessionTable WHERE username = ?1",
        [talker],
        |row| row.get(0),
    )
    .ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Create a minimal test environment with session.db and shard-metadata.json.
    fn setup_test_env(shards: &[(u32, i64, i64)], talker: &str, sort_ts: i64) -> TempDir {
        let dir = TempDir::new().unwrap();
        let root = dir.path();

        // Create session dir + session.db
        let session_dir = root.join("session");
        std::fs::create_dir_all(&session_dir).unwrap();
        let session_path = session_dir.join("session.db");
        let conn = rusqlite::Connection::open(&session_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE SessionTable (username TEXT, sort_timestamp INTEGER, summary TEXT)",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO SessionTable (username, sort_timestamp) VALUES (?1, ?2)",
            rusqlite::params![talker, sort_ts],
        )
        .unwrap();

        // Create message dir + shard files + metadata
        let msg_dir = root.join("message");
        std::fs::create_dir_all(&msg_dir).unwrap();

        let meta_shards: Vec<wx_db::shard_metadata::ShardMeta> = shards
            .iter()
            .map(|&(id, start, end)| {
                // Create a dummy shard file
                std::fs::write(msg_dir.join(format!("message_{id}.db")), b"dummy").unwrap();
                wx_db::shard_metadata::ShardMeta {
                    shard_id: id,
                    start_unix: start,
                    end_unix: end,
                }
            })
            .collect();

        let meta = wx_db::shard_metadata::ShardMetadataFile {
            shards: meta_shards,
            written_at_ns: wx_db::shard_metadata::now_nanos(),
        };
        wx_db::shard_metadata::write_shard_metadata(&msg_dir, &meta).unwrap();

        dir
    }

    #[test]
    fn routes_to_subset_with_since() {
        // 3 shards: [1000,2000], [2001,3000], [3001,i64::MAX]
        let dir = setup_test_env(
            &[(0, 1000, 2000), (1, 2001, 3000), (2, 3001, i64::MAX)],
            "wxid_alice",
            5000,
        );
        let result = route_shards_for_query(dir.path(), "wxid_alice", Some(2500), None);
        // since=2500 → overlaps shard 1 ([2001,3000]) and shard 2 ([3001,MAX])
        // end = sort_timestamp = 5000 → overlaps shards 1, 2
        assert_eq!(result, Some(vec![1, 2]));
    }

    #[test]
    fn routes_to_subset_with_until() {
        let dir = setup_test_env(
            &[(0, 1000, 2000), (1, 2001, 3000), (2, 3001, i64::MAX)],
            "wxid_alice",
            5000,
        );
        let result = route_shards_for_query(dir.path(), "wxid_alice", None, Some(1500));
        // start=0, end=1500 → only overlaps shard 0 [1000,2000]
        assert_eq!(result, Some(vec![0]));
    }

    #[test]
    fn routes_to_subset_with_since_and_until() {
        let dir = setup_test_env(
            &[(0, 1000, 2000), (1, 2001, 3000), (2, 3001, i64::MAX)],
            "wxid_alice",
            5000,
        );
        let result = route_shards_for_query(dir.path(), "wxid_alice", Some(1500), Some(2500));
        // [1500,2500] → overlaps shard 0 and shard 1
        assert_eq!(result, Some(vec![0, 1]));
    }

    #[test]
    fn no_time_bounds_returns_none() {
        let dir = setup_test_env(&[(0, 1000, 2000), (1, 2001, 3000)], "wxid_alice", 5000);
        let result = route_shards_for_query(dir.path(), "wxid_alice", None, None);
        assert!(result.is_none());
    }

    #[test]
    fn unknown_talker_returns_none() {
        let dir = setup_test_env(&[(0, 1000, 2000), (1, 2001, 3000)], "wxid_alice", 5000);
        let result = route_shards_for_query(dir.path(), "wxid_unknown", Some(1500), None);
        assert!(result.is_none());
    }

    #[test]
    fn missing_metadata_returns_none() {
        let dir = TempDir::new().unwrap();
        let result = route_shards_for_query(dir.path(), "wxid_alice", Some(1000), None);
        assert!(result.is_none());
    }

    #[test]
    fn all_shards_match_returns_none() {
        // If routing includes all shards, no benefit
        let dir = setup_test_env(&[(0, 1000, 2000), (1, 2001, i64::MAX)], "wxid_alice", 5000);
        let result = route_shards_for_query(dir.path(), "wxid_alice", Some(500), None);
        // [500, 5000] overlaps both shards → returns None (no reduction)
        assert!(result.is_none());
    }

    #[test]
    fn stale_metadata_returns_none() {
        let dir = setup_test_env(
            &[(0, 1000, 2000), (1, 2001, 3000), (2, 3001, i64::MAX)],
            "wxid_alice",
            5000,
        );

        // Touch a shard file to make it newer than the metadata
        std::thread::sleep(std::time::Duration::from_millis(50));
        let shard_path = dir.path().join("message").join("message_0.db");
        std::fs::write(&shard_path, b"updated").unwrap();

        let result = route_shards_for_query(dir.path(), "wxid_alice", Some(2500), None);
        assert!(result.is_none(), "stale metadata should trigger fallback");
    }
}
