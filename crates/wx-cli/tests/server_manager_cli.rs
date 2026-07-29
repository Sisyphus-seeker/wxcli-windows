#![cfg(target_os = "macos")]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use rusqlite::{params, Connection};
use tempfile::TempDir;

const TEST_KEY_HEX: &str = "abababababababababababababababababababababababababababababababab";
const TEST_ACCOUNT_ID: &str = "wxid_test_account";
const TALKER: &str = "wxid_alice";
const MSG_TABLE: &str = "Msg_29a6db07e8bbdb53f5d54cc3c309f3f1";

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_wx-cli")
}

#[test]
fn help_surface_exposes_server_group_only() {
    let root_help = Command::new(bin())
        .arg("--help")
        .output()
        .expect("run root help");
    assert!(root_help.status.success(), "{root_help:?}");
    let root_help = String::from_utf8_lossy(&root_help.stdout);
    assert!(root_help.contains("server"));
    assert!(!root_help.lines().any(|line| line.trim() == "serve"));

    let server_help = Command::new(bin())
        .args(["server", "--help"])
        .output()
        .expect("run server help");
    assert!(server_help.status.success(), "{server_help:?}");
    let server_help = String::from_utf8_lossy(&server_help.stdout);
    assert!(server_help.contains("run"));
    assert!(server_help.contains("status"));
    assert!(server_help.contains("stop"));
    assert!(server_help.contains("restart"));
    assert!(!server_help.contains("_worker"));
}

#[test]
fn server_run_status_restart_and_stop_round_trip() {
    let fixture = create_fixture();
    let runtime_root = fixture.path().join("runtime");
    let _guard = ManagedServerGuard::new(runtime_root.clone());
    let account_dir = fixture.path().join(TEST_ACCOUNT_ID);
    let port = find_open_port();

    let run = Command::new(bin())
        .args([
            "server",
            "run",
            "--data-dir",
            account_dir.to_str().expect("fixture path utf8"),
            "--key",
            TEST_KEY_HEX,
            "--host",
            "127.0.0.1",
            "--port",
            &port.to_string(),
            "--poll",
            "--poll-ms",
            "1000",
            "--runtime-root",
            runtime_root.to_str().expect("runtime root utf8"),
        ])
        .output()
        .expect("run server");
    assert_runtime_success(&run, &runtime_root);

    let status = server_status_json(&runtime_root);
    assert_eq!(status["status"], "running");
    assert_eq!(status["health"], "healthy");
    assert_eq!(status["ready"], true);
    assert_eq!(status["base_url"], format!("http://127.0.0.1:{port}"));
    assert!(status["pid"].as_u64().unwrap_or_default() > 0);
    assert!(status["cli_version"].as_str().is_some());

    let duplicate = Command::new(bin())
        .args([
            "server",
            "run",
            "--data-dir",
            account_dir.to_str().expect("fixture path utf8"),
            "--key",
            TEST_KEY_HEX,
            "--host",
            "127.0.0.1",
            "--port",
            &port.to_string(),
            "--poll",
            "--poll-ms",
            "1000",
            "--runtime-root",
            runtime_root.to_str().expect("runtime root utf8"),
        ])
        .output()
        .expect("run duplicate server");
    assert_runtime_success(&duplicate, &runtime_root);
    assert!(String::from_utf8_lossy(&duplicate.stdout).contains("already running"));

    let different_config = Command::new(bin())
        .args([
            "server",
            "run",
            "--data-dir",
            account_dir.to_str().expect("fixture path utf8"),
            "--key",
            TEST_KEY_HEX,
            "--host",
            "127.0.0.1",
            "--port",
            &(port + 1).to_string(),
            "--poll",
            "--poll-ms",
            "1000",
            "--runtime-root",
            runtime_root.to_str().expect("runtime root utf8"),
        ])
        .output()
        .expect("run duplicate server with different config");
    assert!(!different_config.status.success(), "{different_config:?}");
    assert!(String::from_utf8_lossy(&different_config.stderr)
        .contains("different launch configuration"));

    let unchanged = server_status_json(&runtime_root);
    assert_eq!(unchanged["base_url"], format!("http://127.0.0.1:{port}"));

    let restart = Command::new(bin())
        .args([
            "server",
            "restart",
            "--runtime-root",
            runtime_root.to_str().expect("runtime root utf8"),
        ])
        .output()
        .expect("restart server");
    assert_runtime_success(&restart, &runtime_root);

    let restarted = server_status_json(&runtime_root);
    assert_eq!(restarted["status"], "running");
    assert_eq!(restarted["health"], "healthy");

    let stop = Command::new(bin())
        .args([
            "server",
            "stop",
            "--runtime-root",
            runtime_root.to_str().expect("runtime root utf8"),
        ])
        .output()
        .expect("stop server");
    assert_runtime_success(&stop, &runtime_root);
    assert!(String::from_utf8_lossy(&stop.stdout).contains("server stopped"));

    let stopped = server_status_json(&runtime_root);
    assert_eq!(stopped["status"], "not_running");
}

#[test]
fn stale_runtime_state_is_reported_and_recovered() {
    let fixture = create_fixture();
    let runtime_root = fixture.path().join("runtime");
    let _guard = ManagedServerGuard::new(runtime_root.clone());
    let account_dir = fixture.path().join(TEST_ACCOUNT_ID);
    let port = find_open_port();

    let run_args = [
        "server",
        "run",
        "--data-dir",
        account_dir.to_str().expect("fixture path utf8"),
        "--key",
        TEST_KEY_HEX,
        "--host",
        "127.0.0.1",
        "--port",
        &port.to_string(),
        "--poll",
        "--poll-ms",
        "1000",
        "--runtime-root",
        runtime_root.to_str().expect("runtime root utf8"),
    ];

    let run = Command::new(bin())
        .args(run_args)
        .output()
        .expect("run server");
    assert_runtime_success(&run, &runtime_root);

    let status = server_status_json(&runtime_root);
    let pid = status["pid"].as_u64().expect("pid in status") as i32;
    let kill_result = unsafe { libc::kill(pid, libc::SIGKILL) };
    assert_eq!(kill_result, 0, "kill stale pid");
    wait_for_pid_exit(pid as u32);

    let stale = server_status_json(&runtime_root);
    assert_eq!(stale["status"], "stale");

    let cleanup = Command::new(bin())
        .args([
            "server",
            "stop",
            "--runtime-root",
            runtime_root.to_str().expect("runtime root utf8"),
        ])
        .output()
        .expect("stop stale server");
    assert!(cleanup.status.success(), "{cleanup:?}");
    assert!(String::from_utf8_lossy(&cleanup.stdout).contains("removed stale server state"));

    let rerun = Command::new(bin())
        .args(run_args)
        .output()
        .expect("rerun server after stale state");
    assert_runtime_success(&rerun, &runtime_root);

    let recovered = server_status_json(&runtime_root);
    assert_eq!(recovered["status"], "running");
    assert_eq!(recovered["health"], "healthy");
}

#[test]
fn live_worker_with_bad_health_does_not_spawn_duplicate_and_can_be_stopped() {
    let fixture = create_fixture();
    let runtime_root = fixture.path().join("runtime");
    let _guard = ManagedServerGuard::new(runtime_root.clone());
    let account_dir = fixture.path().join(TEST_ACCOUNT_ID);
    let port = find_open_port();

    let run_args = [
        "server",
        "run",
        "--data-dir",
        account_dir.to_str().expect("fixture path utf8"),
        "--key",
        TEST_KEY_HEX,
        "--host",
        "127.0.0.1",
        "--port",
        &port.to_string(),
        "--poll",
        "--poll-ms",
        "1000",
        "--runtime-root",
        runtime_root.to_str().expect("runtime root utf8"),
    ];

    let run = Command::new(bin())
        .args(run_args)
        .output()
        .expect("run server");
    assert_runtime_success(&run, &runtime_root);

    let state_path = runtime_root.join("state.json");
    let mut state: serde_json::Value =
        serde_json::from_slice(&fs::read(&state_path).expect("read state json"))
            .expect("parse state json");
    state["base_url"] = serde_json::Value::String(format!("http://127.0.0.1:{}", port + 10));
    state["port"] = serde_json::Value::from((port + 10) as u64);
    fs::write(
        &state_path,
        serde_json::to_vec_pretty(&state).expect("serialize state"),
    )
    .expect("write corrupted state");

    let rerun = Command::new(bin())
        .args(run_args)
        .output()
        .expect("rerun unhealthy live server");
    assert!(!rerun.status.success(), "{rerun:?}");
    assert!(
        String::from_utf8_lossy(&rerun.stderr).contains("still running but unhealthy"),
        "{rerun:?}"
    );

    let stop = Command::new(bin())
        .args([
            "server",
            "stop",
            "--runtime-root",
            runtime_root.to_str().expect("runtime root utf8"),
        ])
        .output()
        .expect("stop unhealthy live server");
    assert!(stop.status.success(), "{stop:?}");
    assert!(String::from_utf8_lossy(&stop.stdout).contains("server stopped"));
}

struct ManagedServerGuard {
    runtime_root: PathBuf,
}

impl ManagedServerGuard {
    fn new(runtime_root: PathBuf) -> Self {
        Self { runtime_root }
    }
}

impl Drop for ManagedServerGuard {
    fn drop(&mut self) {
        let _ = Command::new(bin())
            .args([
                "server",
                "stop",
                "--runtime-root",
                self.runtime_root.to_str().unwrap_or_default(),
            ])
            .output();
    }
}

fn server_status_json(runtime_root: &Path) -> serde_json::Value {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut last = serde_json::Value::Null;
    while Instant::now() < deadline {
        let output = Command::new(bin())
            .args([
                "server",
                "status",
                "--format",
                "json",
                "--runtime-root",
                runtime_root.to_str().expect("runtime root utf8"),
            ])
            .output()
            .expect("run server status");
        assert!(output.status.success(), "{output:?}");
        let parsed: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("parse server status json");
        if matches!(
            parsed["status"].as_str(),
            Some("running" | "stale" | "not_running")
        ) {
            return parsed;
        }
        last = parsed;
        thread::sleep(Duration::from_millis(100));
    }
    last
}

fn assert_runtime_success(output: &std::process::Output, runtime_root: &Path) {
    if output.status.success() {
        return;
    }
    let stderr_log = runtime_root.join("stderr.log");
    let log = fs::read_to_string(&stderr_log).unwrap_or_else(|_| "<no stderr log>".to_string());
    panic!("{output:?}\nworker stderr log:\n{log}");
}

fn wait_for_pid_exit(pid: u32) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        let alive = unsafe { libc::kill(pid as i32, 0) == 0 };
        if !alive {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn create_fixture() -> TempDir {
    let dir = TempDir::new().expect("tempdir");
    let account_dir = dir.path().join(TEST_ACCOUNT_ID);
    let db_root = account_dir.join("db_storage");
    let contact_dir = db_root.join("contact");
    let session_dir = db_root.join("session");
    let message_dir = db_root.join("message");
    let attach_dir = account_dir.join("msg").join("attach");
    let file_dir = account_dir.join("msg").join("file");
    let video_dir = account_dir.join("msg").join("video");

    fs::create_dir_all(&contact_dir).expect("create contact dir");
    fs::create_dir_all(&session_dir).expect("create session dir");
    fs::create_dir_all(&message_dir).expect("create message dir");
    fs::create_dir_all(&attach_dir).expect("create attach dir");
    fs::create_dir_all(&file_dir).expect("create file dir");
    fs::create_dir_all(&video_dir).expect("create video dir");

    let raw_key = test_raw_key();
    create_encrypted_contact_db(&contact_dir.join("contact.db"), &raw_key);
    create_encrypted_session_db(&session_dir.join("session.db"), &raw_key);
    create_encrypted_message_db(&message_dir.join("message_0.db"), &raw_key);

    dir
}

fn test_raw_key() -> [u8; 32] {
    let bytes = hex::decode(TEST_KEY_HEX).expect("decode test key");
    let mut raw_key = [0_u8; 32];
    raw_key.copy_from_slice(&bytes);
    raw_key
}

fn create_encrypted_contact_db(path: &Path, raw_key: &[u8; 32]) {
    create_encrypted_db(
        path,
        raw_key,
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
        |conn| {
            conn.execute(
                "INSERT INTO contact (username, alias, remark, nick_name) VALUES (?1, ?2, ?3, ?4)",
                params![TALKER, "", "", "Alice"],
            )
            .expect("insert contact");
        },
    );
}

fn create_encrypted_session_db(path: &Path, raw_key: &[u8; 32]) {
    create_encrypted_db(
        path,
        raw_key,
        "CREATE TABLE SessionTable (
            username TEXT,
            sort_timestamp INTEGER,
            summary TEXT,
            last_msg_type INTEGER DEFAULT NULL,
            last_msg_sender TEXT DEFAULT NULL,
            last_sender_display_name TEXT DEFAULT NULL
        );",
        |conn| {
            conn.execute(
                "INSERT INTO SessionTable VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    TALKER,
                    1_700_000_000_i64,
                    "fixture summary",
                    None::<i64>,
                    None::<String>,
                    None::<String>,
                ],
            )
            .expect("insert session");
        },
    );
}

fn create_encrypted_message_db(path: &Path, raw_key: &[u8; 32]) {
    create_encrypted_db(
        path,
        raw_key,
        &format!(
            "CREATE TABLE Timestamp (timestamp INTEGER);
            CREATE TABLE Name2Id (
                rowid INTEGER PRIMARY KEY,
                user_name TEXT
            );
            CREATE TABLE [{table}] (
                sort_seq INTEGER,
                server_id INTEGER,
                local_type INTEGER,
                real_sender_id INTEGER,
                create_time INTEGER,
                message_content BLOB,
                packed_info_data BLOB,
                status INTEGER,
                WCDB_CT_message_content INTEGER
            );",
            table = MSG_TABLE
        ),
        |conn| {
            conn.execute(
                "INSERT INTO Timestamp VALUES (?1)",
                params![1_700_000_000_i64],
            )
            .expect("insert timestamp");
            conn.execute(
                "INSERT INTO Name2Id VALUES (?1, ?2)",
                params![1_i64, TALKER],
            )
            .expect("insert name2id");
            conn.execute(
                &format!(
                    "INSERT INTO [{table}] VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                    table = MSG_TABLE
                ),
                params![
                    100_i64,
                    2001_i64,
                    1_i64,
                    1_i64,
                    1_700_000_100_i64,
                    b"plain text" as &[u8],
                    None::<Vec<u8>>,
                    0_i32,
                    None::<i32>,
                ],
            )
            .expect("insert text message");
        },
    );
}

fn create_encrypted_db(
    path: &Path,
    raw_key: &[u8; 32],
    schema_sql: &str,
    seed: impl FnOnce(&Connection),
) {
    let conn = Connection::open(path).expect("open sqlite");
    unsafe {
        let rc = rusqlite::ffi::sqlite3_key(
            conn.handle(),
            raw_key.as_ptr() as *const std::ffi::c_void,
            32,
        );
        assert_eq!(rc, 0, "sqlite3_key failed for {}", path.display());
    }
    conn.execute_batch(schema_sql).expect("apply schema");
    seed(&conn);
}

fn find_open_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().expect("listener addr").port()
}
