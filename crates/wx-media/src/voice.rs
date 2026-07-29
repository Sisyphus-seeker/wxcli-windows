use std::path::Path;

use crate::error::MediaError;
use crate::types::VoiceBlob;

fn voice_table_exists(conn: &rusqlite::Connection) -> Result<bool, MediaError> {
    Ok(conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='VoiceInfo'",
        [],
        |row| row.get::<_, i64>(0),
    )? > 0)
}

fn voice_table_has_chat_name_id(conn: &rusqlite::Connection) -> Result<bool, MediaError> {
    let mut stmt = conn.prepare("PRAGMA table_info([VoiceInfo])")?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        if row.get::<_, String>(1)? == "chat_name_id" {
            return Ok(true);
        }
    }
    Ok(false)
}

fn query_voice_rows(
    conn: &rusqlite::Connection,
    sql: &str,
    params: impl rusqlite::Params,
    svr_id: &str,
) -> Result<Option<VoiceBlob>, MediaError> {
    let mut stmt = conn.prepare(sql)?;
    let mut rows = stmt.query(params)?;

    while let Some(row) = rows.next()? {
        let chat_name_id = row.get::<_, Option<i64>>(0)?;
        let data: Vec<u8> = row.get(1)?;
        if !data.is_empty() {
            return Ok(Some(VoiceBlob {
                svr_id: svr_id.to_string(),
                chat_name_id,
                data,
            }));
        }
    }

    Ok(None)
}

/// Extract a voice BLOB from `media_*.db` files by `svr_id`.
///
/// Scans all `media*.db` files in the given directory (supports `media.db`,
/// `media_0.db`, `media_1.db`, etc.). Returns the first non-empty match.
///
/// Error classification:
/// - [`MediaError::NoMediaDbs`] — directory missing or no media DBs found
/// - [`MediaError::Sqlite`] — all accessible DBs produced SQLite errors
/// - [`MediaError::LookupMiss`] — query succeeded but svr_id not found
pub fn extract_voice(media_dir: &Path, svr_id: &str) -> Result<VoiceBlob, MediaError> {
    let db_paths = find_media_dbs(media_dir)?;

    let mut first_sqlite_err: Option<rusqlite::Error> = None;
    let mut any_queried = false;

    for db_path in &db_paths {
        let conn = match rusqlite::Connection::open_with_flags(
            db_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        ) {
            Ok(c) => c,
            Err(e) => {
                if first_sqlite_err.is_none() {
                    first_sqlite_err = Some(e);
                }
                continue;
            }
        };

        match extract_voice_with_conn(&conn, svr_id) {
            Ok(blob) => return Ok(blob),
            Err(MediaError::LookupMiss(_)) => {
                any_queried = true;
            }
            Err(MediaError::Sqlite(err)) => {
                if first_sqlite_err.is_none() {
                    first_sqlite_err = Some(err);
                }
            }
            Err(other) => return Err(other),
        }
    }

    // If we never successfully queried any DB, report the SQLite error
    if !any_queried {
        if let Some(e) = first_sqlite_err {
            return Err(MediaError::Sqlite(e));
        }
    }

    Err(MediaError::LookupMiss(format!(
        "voice not found for svr_id {svr_id}"
    )))
}

pub fn extract_voice_with_conn(
    conn: &rusqlite::Connection,
    svr_id: &str,
) -> Result<VoiceBlob, MediaError> {
    extract_voice_with_conn_hint(conn, svr_id, None)
}

pub fn extract_voice_with_conn_hint(
    conn: &rusqlite::Connection,
    svr_id: &str,
    chat_name_id_hint: Option<i64>,
) -> Result<VoiceBlob, MediaError> {
    if !voice_table_exists(conn)? {
        return Err(MediaError::SchemaMissing("VoiceInfo table missing".into()));
    }

    let has_chat_name_id = voice_table_has_chat_name_id(conn)?;

    if has_chat_name_id {
        if let Some(chat_name_id) = chat_name_id_hint {
            if let Some(blob) = query_voice_rows(
                conn,
                "SELECT chat_name_id, voice_data FROM VoiceInfo WHERE chat_name_id = ? AND svr_id = ?",
                rusqlite::params![chat_name_id, svr_id],
                svr_id,
            )? {
                return Ok(blob);
            }
        }

        if let Some(blob) = query_voice_rows(
            conn,
            "SELECT chat_name_id, voice_data FROM VoiceInfo WHERE svr_id = ?",
            rusqlite::params![svr_id],
            svr_id,
        )? {
            return Ok(blob);
        }
    } else if let Some(blob) = query_voice_rows(
        conn,
        "SELECT NULL, voice_data FROM VoiceInfo WHERE svr_id = ?",
        rusqlite::params![svr_id],
        svr_id,
    )? {
        return Ok(blob);
    }

    Err(MediaError::LookupMiss(format!(
        "voice not found for svr_id {svr_id}"
    )))
}

/// Find all `media*.db` files in the directory, sorted by name.
pub fn find_media_dbs(dir: &Path) -> Result<Vec<std::path::PathBuf>, MediaError> {
    let entries = std::fs::read_dir(dir).map_err(|_| MediaError::NoMediaDbs(dir.to_path_buf()))?;

    let mut paths: Vec<std::path::PathBuf> = entries
        .filter_map(|e| e.ok())
        .filter(|e| {
            let name = e.file_name();
            let name = name.to_string_lossy();
            // Match: media.db, media_0.db, media_1.db, media_12.db, etc.
            (name == "media.db" || name.starts_with("media_")) && name.ends_with(".db")
        })
        .map(|e| e.path())
        .collect();

    if paths.is_empty() {
        return Err(MediaError::NoMediaDbs(dir.to_path_buf()));
    }

    paths.sort();
    Ok(paths)
}
