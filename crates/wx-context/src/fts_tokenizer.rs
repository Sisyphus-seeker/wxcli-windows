use std::os::raw::{c_char, c_int, c_void};
use std::path::Path;
use std::ptr;

use rusqlite::ffi;

use crate::error::ContextError;
use crate::tokenizer::{tokenize, Token, TokenizerConfig};

// ---------------------------------------------------------------------------
// FTS5 token colocated flag
// ---------------------------------------------------------------------------

const FTS5_TOKEN_COLOCATED: c_int = 0x0001;

// ---------------------------------------------------------------------------
// MmTokenizer struct (C-ABI compatible)
// ---------------------------------------------------------------------------

#[repr(C)]
struct MmTokenizer {
    config: TokenizerConfig,
}

// ---------------------------------------------------------------------------
// C-ABI callbacks
// ---------------------------------------------------------------------------

unsafe extern "C" fn x_create(
    user_data: *mut c_void,
    az_arg: *mut *const c_char,
    n_arg: c_int,
    pp_out: *mut *mut ffi::Fts5Tokenizer,
) -> c_int {
    let _ = user_data;
    let mut config = TokenizerConfig::default();

    // Parse azArg parameters
    if !az_arg.is_null() && n_arg > 0 {
        for i in 0..n_arg as usize {
            let arg_ptr = *az_arg.add(i);
            if arg_ptr.is_null() {
                continue;
            }
            let Ok(arg) = std::ffi::CStr::from_ptr(arg_ptr).to_str() else {
                continue;
            };
            match arg {
                "enable_special_char" => config.enable_special_char = true,
                "enable_num_token" => config.enable_num_token = true,
                // disable_pinyin and disable_origin are deferred to Task 8 (contact pinyin support)
                // Unknown params: silently ignored for forward-compatibility
                _ => {}
            }
        }
    }

    let tok = Box::new(MmTokenizer { config });
    *pp_out = Box::into_raw(tok) as *mut ffi::Fts5Tokenizer;
    ffi::SQLITE_OK as c_int
}

unsafe extern "C" fn x_delete(tokenizer: *mut ffi::Fts5Tokenizer) {
    if !tokenizer.is_null() {
        drop(Box::from_raw(tokenizer as *mut MmTokenizer));
    }
}

unsafe extern "C" fn x_tokenize(
    tokenizer: *mut ffi::Fts5Tokenizer,
    ctx: *mut c_void,
    _flags: c_int,
    text: *const c_char,
    n_text: c_int,
    x_token: Option<
        unsafe extern "C" fn(*mut c_void, c_int, *const c_char, c_int, c_int, c_int) -> c_int,
    >,
) -> c_int {
    if tokenizer.is_null() || text.is_null() {
        return ffi::SQLITE_OK as c_int;
    }

    let mm = &*(tokenizer as *mut MmTokenizer);

    let text_slice = if n_text < 0 {
        // null-terminated
        let cstr = std::ffi::CStr::from_ptr(text);
        cstr.to_bytes()
    } else {
        std::slice::from_raw_parts(text as *const u8, n_text as usize)
    };

    let Some(x_tok_fn) = x_token else {
        return ffi::SQLITE_OK as c_int;
    };

    let tokens: Vec<Token> = tokenize(text_slice, &mm.config);

    for tok in &tokens {
        let tflags = if tok.colocated {
            FTS5_TOKEN_COLOCATED
        } else {
            0
        };
        let rc = x_tok_fn(
            ctx,
            tflags,
            tok.text.as_ptr() as *const c_char,
            tok.text.len() as c_int,
            tok.start as c_int,
            tok.end as c_int,
        );
        if rc != ffi::SQLITE_OK as c_int {
            return rc;
        }
    }

    ffi::SQLITE_OK as c_int
}

// ---------------------------------------------------------------------------
// Internal helper: get_fts5_api + register
// ---------------------------------------------------------------------------

unsafe fn errmsg(db: *mut ffi::sqlite3) -> String {
    let ptr = ffi::sqlite3_errmsg(db);
    if ptr.is_null() {
        return "(no message)".into();
    }
    std::ffi::CStr::from_ptr(ptr).to_string_lossy().into_owned()
}

unsafe fn get_fts5_api(db: *mut ffi::sqlite3) -> Result<*mut ffi::fts5_api, String> {
    let sql = c"SELECT fts5(?1)";
    let mut stmt: *mut ffi::sqlite3_stmt = ptr::null_mut();
    let rc = ffi::sqlite3_prepare_v2(db, sql.as_ptr(), -1, &mut stmt, ptr::null_mut());
    if rc != ffi::SQLITE_OK as c_int {
        return Err(format!("prepare fts5 query: rc={rc} msg={}", errmsg(db)));
    }

    let mut api: *mut ffi::fts5_api = ptr::null_mut();
    let rc = ffi::sqlite3_bind_pointer(
        stmt,
        1,
        &mut api as *mut _ as *mut c_void,
        c"fts5_api_ptr".as_ptr(),
        None,
    );
    if rc != ffi::SQLITE_OK as c_int {
        ffi::sqlite3_finalize(stmt);
        return Err(format!("bind_pointer: rc={rc} msg={}", errmsg(db)));
    }

    let rc = ffi::sqlite3_step(stmt);
    ffi::sqlite3_finalize(stmt);
    if rc != ffi::SQLITE_ROW as c_int {
        return Err(format!("step fts5: rc={rc} msg={}", errmsg(db)));
    }

    if api.is_null() {
        return Err("fts5_api unavailable".into());
    }

    Ok(api)
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Register the real `MMFtsTokenizer` on `conn`.
///
/// This replaces the no-op tokenizer in `wal_patch.rs` and enables actual
/// FTS5 MATCH queries against WeChat's native `message_fts.db`.
pub fn register_mm_fts_tokenizer(conn: &rusqlite::Connection) -> Result<(), String> {
    unsafe {
        let db = conn.handle();
        let api = get_fts5_api(db)?;

        let mut tok = ffi::fts5_tokenizer {
            xCreate: Some(x_create),
            xDelete: Some(x_delete),
            xTokenize: Some(x_tokenize),
        };
        let name = c"MMFtsTokenizer";
        let x_create_tok = (*api)
            .xCreateTokenizer
            .ok_or("fts5_api.xCreateTokenizer is NULL")?;
        let rc = x_create_tok(api, name.as_ptr(), ptr::null_mut(), &mut tok, None);
        if rc != ffi::SQLITE_OK as c_int {
            return Err(format!(
                "xCreateTokenizer failed: rc={rc} msg={}",
                errmsg(db)
            ));
        }

        Ok(())
    }
}

/// Open a read-only connection to an FTS database with `MMFtsTokenizer` registered.
pub fn open_fts_connection(path: &Path) -> Result<rusqlite::Connection, ContextError> {
    open_fts_connection_with_key(path, None)
}

/// Open a read-only connection to an FTS database (optionally encrypted)
/// with `MMFtsTokenizer` registered.
pub fn open_fts_connection_with_key(
    path: &Path,
    raw_key: Option<&[u8; 32]>,
) -> Result<rusqlite::Connection, ContextError> {
    if !path.exists() {
        return Err(ContextError::Sqlite(format!(
            "FTS database not found: {}",
            path.display()
        )));
    }
    let conn =
        rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|e| ContextError::Sqlite(e.to_string()))?;

    if let Some(key) = raw_key {
        #[cfg(not(target_os = "macos"))]
        {
            let _ = key;
            return Err(ContextError::Sqlite(
                "direct encrypted FTS open is unavailable on this platform".into(),
            ));
        }

        #[cfg(target_os = "macos")]
        {
            unsafe {
                let rc = ffi::sqlite3_key(conn.handle(), key.as_ptr() as *const c_void, 32);
                if rc != 0 {
                    return Err(ContextError::Sqlite(format!("sqlite3_key failed: rc={rc}")));
                }
            }
            conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| {
                r.get::<_, i64>(0)
            })
            .map_err(|_| {
                ContextError::Sqlite("incorrect key or not an encrypted FTS database".into())
            })?;
            conn.execute_batch("PRAGMA query_only = ON")
                .map_err(|e| ContextError::Sqlite(e.to_string()))?;
        }
    }

    register_mm_fts_tokenizer(&conn).map_err(ContextError::Sqlite)?;

    Ok(conn)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn open_test_conn() -> Connection {
        Connection::open_in_memory().unwrap()
    }

    // Test 1: register_mm_fts_tokenizer succeeds on a fresh connection
    #[test]
    fn register_succeeds() {
        let conn = open_test_conn();
        let result = register_mm_fts_tokenizer(&conn);
        assert!(result.is_ok(), "registration should succeed: {result:?}");
    }

    // Test 2: After registration, CREATE VIRTUAL TABLE with MMFtsTokenizer succeeds
    #[test]
    fn create_fts5_table_with_tokenizer() {
        let conn = open_test_conn();
        register_mm_fts_tokenizer(&conn).unwrap();
        conn.execute_batch(
            "CREATE VIRTUAL TABLE t USING fts5(content, tokenize='MMFtsTokenizer disable_pinyin');",
        )
        .expect("should create FTS5 table with MMFtsTokenizer");
    }

    // Test 3: INSERT + MATCH for CJK works
    #[test]
    fn fts_match_cjk() {
        let conn = open_test_conn();
        register_mm_fts_tokenizer(&conn).unwrap();
        conn.execute_batch(
            "CREATE VIRTUAL TABLE t USING fts5(content, tokenize='MMFtsTokenizer');
             INSERT INTO t(content) VALUES ('你好world');",
        )
        .unwrap();
        let count: i64 = conn
            .query_row("SELECT count(*) FROM t WHERE t MATCH '\"你\"'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(count, 1, "CJK MATCH should find the row");
    }

    // Test 4: INSERT + MATCH with English stemming: insert "running fast", MATCH "run" returns the row
    #[test]
    fn fts_match_english_stemming() {
        let conn = open_test_conn();
        register_mm_fts_tokenizer(&conn).unwrap();
        conn.execute_batch(
            "CREATE VIRTUAL TABLE t USING fts5(content, tokenize='MMFtsTokenizer');
             INSERT INTO t(content) VALUES ('running fast');",
        )
        .unwrap();
        let count: i64 = conn
            .query_row("SELECT count(*) FROM t WHERE t MATCH 'run'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(count, 1, "Stemming: 'run' should match 'running'");
    }

    // Test 5: open_fts_connection on non-existent path returns error
    #[test]
    fn open_nonexistent_path_errors() {
        let result = open_fts_connection(Path::new("/nonexistent/path/fts.db"));
        assert!(result.is_err(), "should error on non-existent path");
    }

    #[test]
    fn real_tokenizer_fts_round_trip() {
        let conn = open_test_conn();
        register_mm_fts_tokenizer(&conn).unwrap();
        conn.execute_batch(
            "CREATE VIRTUAL TABLE msg USING fts5(body, tokenize='MMFtsTokenizer disable_pinyin');
             INSERT INTO msg VALUES ('你好世界');
             INSERT INTO msg VALUES ('hello world running');",
        )
        .unwrap();

        // CJK unigram search
        let n: i64 = conn
            .query_row(
                "SELECT count(*) FROM msg WHERE msg MATCH '\"你\"'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 1);

        // English stemmed search
        let n: i64 = conn
            .query_row("SELECT count(*) FROM msg WHERE msg MATCH 'run'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(n, 1);
    }
}
