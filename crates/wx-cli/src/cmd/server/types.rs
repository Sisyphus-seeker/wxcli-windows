use std::path::PathBuf;

use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};

use crate::OutputFormat;

#[derive(Args, Clone, Debug)]
pub struct ServerRunArgs {
    /// 32-byte hex key (overrides KeyStore lookup)
    #[arg(short, long)]
    pub key: Option<String>,

    /// WeChat data directory (auto-detect if omitted)
    #[arg(short, long)]
    pub data_dir: Option<PathBuf>,

    /// Account directory name or base account ID
    #[arg(long)]
    pub account: Option<String>,

    /// Force mtime polling instead of fsnotify
    #[arg(long, conflicts_with = "fsnotify")]
    pub poll: bool,

    /// Force fsnotify backend (opt-in on macOS, where polling is the default)
    #[arg(long, conflicts_with = "poll")]
    pub fsnotify: bool,

    /// Polling interval in milliseconds
    #[arg(long, default_value = "2000")]
    pub poll_ms: u64,

    /// Listen host address
    #[arg(long, default_value = "127.0.0.1")]
    pub host: String,

    /// Listen port
    #[arg(long, default_value = "9100")]
    pub port: u16,

    /// Bearer token for authentication (required when --host is not loopback)
    #[arg(long)]
    pub token: Option<String>,

    /// Internal runtime root override for tests/non-public plumbing
    #[arg(long, hide = true)]
    pub runtime_root: Option<PathBuf>,
}

#[derive(Args, Clone, Debug)]
pub struct ServerStatusArgs {
    /// Output format
    #[arg(long, default_value = "text", value_enum)]
    pub format: OutputFormat,

    /// Internal runtime root override for tests/non-public plumbing
    #[arg(long, hide = true)]
    pub runtime_root: Option<PathBuf>,
}

#[derive(Args, Clone, Debug)]
pub struct ServerStopArgs {
    /// Internal runtime root override for tests/non-public plumbing
    #[arg(long, hide = true)]
    pub runtime_root: Option<PathBuf>,
}

#[derive(Args, Clone, Debug)]
pub struct ServerRestartArgs {
    /// Internal runtime root override for tests/non-public plumbing
    #[arg(long, hide = true)]
    pub runtime_root: Option<PathBuf>,
}

#[derive(Args, Clone, Debug)]
pub struct ServerWorkerArgs {
    /// 32-byte hex key (overrides KeyStore lookup)
    #[arg(short, long)]
    pub key: Option<String>,

    /// WeChat data directory (auto-detect if omitted)
    #[arg(short, long)]
    pub data_dir: Option<PathBuf>,

    /// Account directory name or base account ID
    #[arg(long)]
    pub account: Option<String>,

    /// Force mtime polling instead of fsnotify
    #[arg(long, conflicts_with = "fsnotify")]
    pub poll: bool,

    /// Force fsnotify backend (opt-in on macOS, where polling is the default)
    #[arg(long, conflicts_with = "poll")]
    pub fsnotify: bool,

    /// Polling interval in milliseconds
    #[arg(long, default_value = "2000")]
    pub poll_ms: u64,

    /// Listen host address
    #[arg(long, default_value = "127.0.0.1")]
    pub host: String,

    /// Listen port
    #[arg(long, default_value = "9100")]
    pub port: u16,

    /// Bearer token for authentication (required when --host is not loopback)
    #[arg(long)]
    pub token: Option<String>,

    /// Internal runtime root override for tests/non-public plumbing
    #[arg(long, hide = true)]
    pub runtime_root: Option<PathBuf>,

    /// Internal worker identity used to verify the managed process
    #[arg(long, hide = true)]
    pub worker_id: Option<String>,
}

#[derive(Subcommand, Clone, Debug)]
pub enum ServerAction {
    /// Start the managed HTTP service
    Run(ServerRunArgs),
    /// Show managed service status
    Status(ServerStatusArgs),
    /// Stop the managed HTTP service
    Stop(ServerStopArgs),
    /// Restart the managed HTTP service
    Restart(ServerRestartArgs),
    /// Hidden foreground worker for the service manager and integration tests
    #[command(name = "_worker", hide = true)]
    Worker(ServerWorkerArgs),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServerLaunchConfig {
    pub key: Option<String>,
    pub data_dir: Option<PathBuf>,
    pub account: Option<String>,
    pub poll: bool,
    pub fsnotify: bool,
    pub poll_ms: u64,
    pub host: String,
    pub port: u16,
    pub token: Option<String>,
}

impl From<ServerRunArgs> for ServerLaunchConfig {
    fn from(value: ServerRunArgs) -> Self {
        Self {
            key: value.key,
            data_dir: value.data_dir,
            account: value.account,
            poll: value.poll,
            fsnotify: value.fsnotify,
            poll_ms: value.poll_ms,
            host: value.host,
            port: value.port,
            token: value.token,
        }
    }
}

impl From<ServerWorkerArgs> for ServerLaunchConfig {
    fn from(value: ServerWorkerArgs) -> Self {
        Self {
            key: value.key,
            data_dir: value.data_dir,
            account: value.account,
            poll: value.poll,
            fsnotify: value.fsnotify,
            poll_ms: value.poll_ms,
            host: value.host,
            port: value.port,
            token: value.token,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeAccountState {
    pub wxid: String,
    pub name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorkerLifecycle {
    Starting,
    Running,
    Stopping,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServerRuntimeState {
    pub pid: u32,
    pub worker_id: String,
    pub lifecycle: WorkerLifecycle,
    pub ready: bool,
    pub host: String,
    pub port: u16,
    pub base_url: String,
    pub token_configured: bool,
    pub cli_version: String,
    pub current_account: Option<RuntimeAccountState>,
    pub stdout_log: PathBuf,
    pub stderr_log: PathBuf,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServerHealthPayload {
    pub ready: bool,
    pub worker_id: String,
    pub cli_version: String,
    pub current_account: RuntimeAccountState,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServerHealthState {
    Healthy,
    NotReady,
    Unreachable,
    Skipped,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServerStatusKind {
    NotRunning,
    Starting,
    Running,
    Stopping,
    Stale,
    Broken,
}

#[derive(Clone, Debug, Serialize)]
pub struct ServerStatusReport {
    pub status: ServerStatusKind,
    /// Default: `AppPaths::server_state_dir()`. When `--runtime-root` is
    /// specified, ALL runtime files (state + config + lock + logs) go under
    /// this root. In default mode, logs go to `AppPaths::logs_dir()/server/`.
    pub runtime_root: PathBuf,
    pub state_file: PathBuf,
    pub config_file: PathBuf,
    pub stdout_log: PathBuf,
    pub stderr_log: PathBuf,
    pub pid: Option<u32>,
    pub base_url: Option<String>,
    pub ready: bool,
    pub health: ServerHealthState,
    pub cli_version: Option<String>,
    pub current_account: Option<RuntimeAccountState>,
    pub notes: Vec<String>,
}
