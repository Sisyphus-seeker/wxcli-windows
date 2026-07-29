//! Shard metadata types and read/write helpers for persistent shard time-range cache.
//!
//! The sidecar file `shard-metadata.json` is written alongside decrypted message
//! shard DBs. It records each shard's time range so that callers can route queries
//! to a minimal subset of shards without opening every DB.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Time-range metadata for a single message shard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardMeta {
    pub shard_id: u32,
    pub start_unix: i64,
    pub end_unix: i64,
}

/// Persistent shard metadata file contents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardMetadataFile {
    pub shards: Vec<ShardMeta>,
    /// Unix nanoseconds when this metadata was written.
    pub written_at_ns: u128,
}

const SIDECAR_FILENAME: &str = "shard-metadata.json";

/// Read shard metadata from `dir/shard-metadata.json`.
/// Returns `None` on any error (missing file, corrupt JSON, IO error).
pub fn read_shard_metadata(dir: &Path) -> Option<ShardMetadataFile> {
    let path = dir.join(SIDECAR_FILENAME);
    let data = std::fs::read_to_string(&path).ok()?;
    serde_json::from_str(&data).ok()
}

/// Atomically write shard metadata to `dir/shard-metadata.json`.
/// Writes to a `.tmp` file first, then renames.
pub fn write_shard_metadata(dir: &Path, meta: &ShardMetadataFile) -> Result<(), std::io::Error> {
    let path = dir.join(SIDECAR_FILENAME);
    let tmp_path = dir.join(format!("{SIDECAR_FILENAME}.tmp"));
    let data = serde_json::to_string_pretty(meta).map_err(std::io::Error::other)?;
    std::fs::write(&tmp_path, data)?;
    std::fs::rename(&tmp_path, &path)?;
    Ok(())
}

/// Build a `ShardMetadataFile` timestamp (current time in nanoseconds since epoch).
pub fn now_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn roundtrip_write_read() {
        let dir = TempDir::new().unwrap();
        let meta = ShardMetadataFile {
            shards: vec![
                ShardMeta {
                    shard_id: 0,
                    start_unix: 1000,
                    end_unix: 2000,
                },
                ShardMeta {
                    shard_id: 1,
                    start_unix: 2001,
                    end_unix: 3000,
                },
            ],
            written_at_ns: 123456789,
        };

        write_shard_metadata(dir.path(), &meta).unwrap();
        let loaded = read_shard_metadata(dir.path()).unwrap();

        assert_eq!(loaded.shards.len(), 2);
        assert_eq!(loaded.shards[0].shard_id, 0);
        assert_eq!(loaded.shards[0].start_unix, 1000);
        assert_eq!(loaded.shards[1].shard_id, 1);
        assert_eq!(loaded.shards[1].end_unix, 3000);
        assert_eq!(loaded.written_at_ns, 123456789);
    }

    #[test]
    fn read_nonexistent_returns_none() {
        let dir = TempDir::new().unwrap();
        assert!(read_shard_metadata(dir.path()).is_none());
    }

    #[test]
    fn read_corrupt_json_returns_none() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("shard-metadata.json"), "not valid json").unwrap();
        assert!(read_shard_metadata(dir.path()).is_none());
    }
}
