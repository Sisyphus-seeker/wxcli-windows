use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use lru::LruCache;
use rusqlite::Connection;
use tokio::sync::{broadcast, mpsc};
use tokio_util::sync::CancellationToken;
use wx_context::{ContactResolver, VisibilityIndex};
use wx_db::WechatDb;
use wx_media::DatDecryptOptions;

use super::event::SseEvent;
use super::refresh::RefreshTrigger;

#[derive(Clone)]
pub struct CachedVoicePayload {
    pub bytes: Vec<u8>,
    pub content_type: &'static str,
}

#[derive(Clone)]
pub struct CurrentAccount {
    pub wxid: String,
    pub name: String,
}

pub struct AppState {
    /// WechatDb behind std::sync::Mutex — accessed only via spawn_blocking.
    pub db: Arc<std::sync::Mutex<WechatDb>>,
    /// Self wxid for direction enrichment.
    pub self_wxid: String,
    /// Active account metadata for the currently served dataset.
    pub current_account: CurrentAccount,
    /// Stable per-worker identity persisted in runtime state and returned by health probes.
    pub worker_id: String,
    /// Shared CLI version string used by health/status surfaces.
    pub cli_version: String,
    /// Contact name resolver (read-only after construction).
    pub resolver: Arc<ContactResolver>,
    /// Compiled talker-level visibility rules for this worker.
    pub visibility: Arc<VisibilityIndex>,
    /// Broadcast channel for SSE events.
    pub broadcast_tx: broadcast::Sender<Arc<SseEvent>>,
    /// Optional Bearer token for auth.
    pub auth_token: Option<String>,
    /// Bridge initialization complete flag. SSE returns 503 until true.
    pub ready: AtomicBool,
    /// Channel for bridge to signal refresh task.
    /// Held here to keep the sender alive; bridge receives its own clone directly.
    #[allow(dead_code)]
    pub refresh_tx: mpsc::Sender<RefreshTrigger>,
    /// Shutdown coordination token — cancelled on SIGTERM/SIGINT.
    pub shutdown: CancellationToken,
    /// Independent FTS connection outside the main WechatDb Mutex.
    /// Used by handler_search to avoid holding the main lock during FTS queries.
    /// Wrapped in its own Mutex for thread-safe reopen.
    pub fts_conn: Option<Arc<std::sync::Mutex<Connection>>>,
    /// Root attach directory for `.dat` image lookup.
    pub attach_dir: PathBuf,
    /// Directory containing `media*.db` voice shards for the active mode.
    pub media_db_dir: PathBuf,
    /// Root file directory for file fallback lookup.
    pub file_dir: PathBuf,
    /// Root video directory for video fallback lookup.
    pub video_dir: PathBuf,
    /// `hardlink.db` path for the active mode.
    pub hardlink_db_path: PathBuf,
    /// Cached connection to `hardlink.db` — lazily opened and cleared on refresh.
    pub hardlink_db_conn: Arc<std::sync::Mutex<Option<Connection>>>,
    /// Optional raw key for direct encrypted media access.
    pub raw_key: Option<[u8; 32]>,
    /// Image `.dat` decryption options shared by media handlers.
    pub dat_decrypt: DatDecryptOptions,
    /// Small in-memory cache for transcoded voice responses, keyed by `server_id:format`.
    pub voice_cache: Arc<std::sync::Mutex<LruCache<String, CachedVoicePayload>>>,
    /// Per-talker cached XOR keys for image `.dat` lookup.
    pub image_xor_cache: Arc<std::sync::Mutex<LruCache<String, Option<u8>>>>,
    /// Lazily initialized name2id cache for FTS search resolution.
    /// Cleared on FTS reopen so stale data doesn't persist.
    pub name2id_cache: Arc<std::sync::Mutex<Option<HashMap<i64, String>>>>,
    /// Lazily initialized list of media database paths for voice lookup.
    /// Cleared on refresh so new media DBs are discovered.
    pub media_db_paths: Arc<std::sync::Mutex<Option<Vec<PathBuf>>>>,
}
