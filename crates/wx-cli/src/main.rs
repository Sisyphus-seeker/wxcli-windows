use std::path::PathBuf;

use clap::{Args, CommandFactory, FromArgMatches, Parser, Subcommand, ValueEnum};

use crate::cmd::server::ServerAction;
use crate::cmd::thin_client::ThinClientCliArgs;

mod cmd;
pub(crate) mod contact_id;
mod output;
pub(crate) mod schema;
pub(crate) mod settings;
mod util;
mod version;
pub(crate) mod visibility_projection;

#[derive(Parser)]
#[command(
    name = "wx-cli",
    about = "WeChat database decryption tool (macOS 4.1.x)"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Args, Clone, Debug, Default)]
struct ServerRoutingArgs {
    /// Reuse a running server instance at this base URL (default: http://127.0.0.1:9100)
    #[arg(long)]
    server_url: Option<String>,

    /// Bearer token for the running server instance
    #[arg(long)]
    server_token: Option<String>,

    /// Only use the running server instance; do not fall back to local queries
    #[arg(long, conflicts_with = "no_server")]
    server_only: bool,

    /// Force local direct-query mode even if a server instance is available
    #[arg(long, conflicts_with = "server_only")]
    no_server: bool,
}

impl From<ServerRoutingArgs> for ThinClientCliArgs {
    fn from(value: ServerRoutingArgs) -> Self {
        Self {
            server_url: value.server_url,
            server_token: value.server_token,
            server_only: value.server_only,
            no_server: value.no_server,
        }
    }
}

#[derive(Subcommand)]
enum Commands {
    /// Manage encryption keys
    Key {
        #[command(subcommand)]
        action: KeyAction,
    },
    /// Decrypt WeChat databases
    Decrypt {
        /// 32-byte hex key (overrides KeyStore lookup)
        #[arg(short, long)]
        key: Option<String>,

        /// WeChat data directory (auto-detect if omitted)
        #[arg(short, long)]
        data_dir: Option<PathBuf>,

        /// Account directory name or base account ID
        #[arg(long)]
        account: Option<String>,

        /// Output directory (default: cache dir)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Only re-decrypt files modified since last run
        #[arg(long)]
        incremental: bool,
    },
    /// Show info about a database file
    Info {
        /// Path to a WeChat database file
        db_file: PathBuf,
    },
    /// Media operations (image decrypt, hardlink query, voice extract)
    Media {
        #[command(subcommand)]
        action: MediaAction,
    },
    /// Watch for real-time session changes in an encrypted WeChat database
    Watch {
        /// 32-byte hex key (overrides KeyStore lookup)
        #[arg(short, long)]
        key: Option<String>,

        /// WeChat data directory (auto-detect if omitted)
        #[arg(short, long)]
        data_dir: Option<PathBuf>,

        /// Account directory name or base account ID
        #[arg(long)]
        account: Option<String>,

        /// Force mtime polling instead of fsnotify
        #[arg(long, conflicts_with = "fsnotify")]
        poll: bool,

        /// Force fsnotify backend (opt-in on macOS, where polling is the default)
        #[arg(long, conflicts_with = "poll")]
        fsnotify: bool,

        /// Polling interval in milliseconds
        #[arg(long, default_value = "2000")]
        poll_ms: u64,

        /// Output format
        #[arg(long, default_value = "text", value_enum)]
        format: OutputFormat,

        /// Show hidden contacts (bypass contact hiding rules)
        #[arg(long)]
        show_hidden: bool,
    },
    /// Manage the long-running HTTP API service
    Server {
        #[command(subcommand)]
        action: ServerAction,
    },
    /// Query recent sessions (conversations)
    Sessions {
        /// WeChat data directory (auto-detect if omitted)
        #[arg(short, long)]
        data_dir: Option<PathBuf>,
        /// Account directory name or base account ID
        #[arg(long)]
        account: Option<String>,
        /// 32-byte hex key (overrides KeyStore lookup)
        #[arg(short, long)]
        key: Option<String>,
        /// Maximum number of results (overridden by --all)
        #[arg(long, default_value = "20")]
        limit: usize,
        /// Pagination offset
        #[arg(long, default_value = "0")]
        offset: usize,
        /// Sort order
        #[arg(long, default_value = "desc", value_enum)]
        order: SortOrderArg,
        /// Return up to 20,000 results (overrides --limit)
        #[arg(long)]
        all: bool,
        /// Output format
        #[arg(long, default_value = "text", value_enum)]
        format: OutputFormat,
        /// Show hidden contacts (bypass contact hiding rules)
        #[arg(long)]
        show_hidden: bool,

        #[command(flatten)]
        server: ServerRoutingArgs,
    },
    /// Search contacts by name, wxid, phone, labels, or other fields
    Contacts {
        /// WeChat data directory (auto-detect if omitted)
        #[arg(short, long)]
        data_dir: Option<PathBuf>,
        /// Account directory name or base account ID
        #[arg(long)]
        account: Option<String>,
        /// 32-byte hex key (overrides KeyStore lookup)
        #[arg(short, long)]
        key: Option<String>,
        /// Search keyword (matches name, wxid, phone, labels, memo, signature, region)
        #[arg(long)]
        search: Option<String>,
        /// Maximum number of results (overridden by --all)
        #[arg(long, default_value = "50")]
        limit: usize,
        /// Pagination offset
        #[arg(long, default_value = "0")]
        offset: usize,
        /// Return up to 20,000 results (overrides --limit)
        #[arg(long)]
        all: bool,
        /// Output format
        #[arg(long, default_value = "text", value_enum)]
        format: OutputFormat,
        /// Show hidden contacts (bypass contact hiding rules)
        #[arg(long)]
        show_hidden: bool,

        #[command(flatten)]
        server: ServerRoutingArgs,
    },
    /// Query chat messages for a contact or group
    Query {
        /// Contact name, wxid, or chatroom ID
        contact: String,
        /// WeChat data directory (auto-detect if omitted)
        #[arg(short, long)]
        data_dir: Option<PathBuf>,
        /// Account directory name or base account ID
        #[arg(long)]
        account: Option<String>,
        /// 32-byte hex key (overrides KeyStore lookup)
        #[arg(short, long)]
        key: Option<String>,
        /// Start time (Unix seconds)
        #[arg(long, conflicts_with_all = ["around_sort_seq", "around_server_id", "after_sort_seq"])]
        since: Option<i64>,
        /// End time (Unix seconds)
        #[arg(long, conflicts_with_all = ["around_sort_seq", "around_server_id", "after_sort_seq"])]
        until: Option<i64>,
        /// Message type filter (text/image/voice/video/emoji/app/system/revoke or numeric, e.g. 49)
        #[arg(long = "type")]
        msg_type: Option<String>,
        /// Maximum number of results (overridden by --all)
        #[arg(long, default_value = "50")]
        limit: usize,
        /// Pagination offset
        #[arg(long, default_value = "0")]
        offset: usize,
        /// Sort order
        #[arg(long, default_value = "desc", value_enum)]
        order: SortOrderArg,
        /// Return up to 20,000 results (overrides --limit)
        #[arg(long, conflicts_with_all = ["around_sort_seq", "around_server_id", "after_sort_seq"])]
        all: bool,
        /// Output format
        #[arg(long, default_value = "text", value_enum)]
        format: OutputFormat,
        /// Show N messages before and after this sort_seq
        #[arg(long, conflicts_with_all = ["since", "until", "all", "around_server_id", "after_sort_seq"])]
        around_sort_seq: Option<i64>,
        /// Show N messages before and after the message with this server_id
        #[arg(long, conflicts_with_all = ["since", "until", "all", "around_sort_seq", "after_sort_seq"])]
        around_server_id: Option<i64>,
        /// Context window size (messages before/after --around-*, default 50)
        #[arg(long)]
        context: Option<usize>,
        /// Return messages after this sort_seq (incremental pull, ASC order)
        #[arg(long, conflicts_with_all = ["since", "until", "all", "around_sort_seq", "around_server_id"])]
        after_sort_seq: Option<i64>,
        /// Show hidden contacts (bypass contact hiding rules)
        #[arg(long)]
        show_hidden: bool,

        #[command(flatten)]
        server: ServerRoutingArgs,
    },
    /// Export a conversation to TXT or JSON with media files
    Export {
        /// Contact name, wxid, or chatroom ID
        contact: String,
        /// Output directory
        #[arg(short, long)]
        output: PathBuf,
        /// WeChat data directory (auto-detect if omitted)
        #[arg(short, long)]
        data_dir: Option<PathBuf>,
        /// Account directory name or base account ID
        #[arg(long)]
        account: Option<String>,
        /// 32-byte hex key (overrides KeyStore lookup)
        #[arg(short, long)]
        key: Option<String>,
        /// Start time filter (Unix seconds)
        #[arg(long)]
        since: Option<i64>,
        /// End time filter (Unix seconds)
        #[arg(long)]
        until: Option<i64>,
        /// Maximum number of results (overridden by --all)
        #[arg(long, default_value = "50")]
        limit: usize,
        /// Pagination offset
        #[arg(long, default_value = "0")]
        offset: usize,
        /// Sort order (default: asc for chronological export)
        #[arg(long, default_value = "asc", value_enum)]
        order: SortOrderArg,
        /// Export all messages (paged internally; overrides --limit)
        #[arg(long)]
        all: bool,
        /// Output format
        #[arg(long, default_value = "txt", value_enum)]
        format: ExportFormat,
        /// Skip media file export (text-only, faster)
        #[arg(long)]
        no_media: bool,
        /// Max parallel threads for media resolve (default: min(CPU, 4), 1 = serial)
        #[arg(long)]
        parallel: Option<usize>,
        /// Show emoji/sticker detail instead of [动画表情]
        #[arg(long)]
        show_emoji: bool,
        /// Show hidden contacts (bypass contact hiding rules)
        #[arg(long)]
        show_hidden: bool,
    },
    /// Full-text search across all conversations
    Search {
        /// Search keyword
        keyword: String,
        /// WeChat data directory (auto-detect if omitted)
        #[arg(short, long)]
        data_dir: Option<PathBuf>,
        /// Account directory name or base account ID
        #[arg(long)]
        account: Option<String>,
        /// 32-byte hex key (overrides KeyStore lookup)
        #[arg(short, long)]
        key: Option<String>,
        /// Maximum number of results (overridden by --all)
        #[arg(long, default_value = "20")]
        limit: usize,
        /// Pagination offset
        #[arg(long, default_value = "0")]
        offset: usize,
        /// Return up to 20,000 results (overrides --limit)
        #[arg(long)]
        all: bool,
        /// Output format
        #[arg(long, default_value = "text", value_enum)]
        format: OutputFormat,

        #[command(flatten)]
        server: ServerRoutingArgs,
    },
    /// Decrypt .dat image file(s) (shortcut for `media decrypt-dat`)
    #[command(name = "decode-image")]
    DecodeImage {
        /// Input .dat file or directory of .dat files
        input: PathBuf,
        /// Output file or directory (auto-named if omitted)
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Account directory name for KeyStore V2 key lookup
        #[arg(long)]
        account: Option<String>,
        /// WeChat account data directory for automatic V2 key derivation
        #[arg(short, long)]
        data_dir: Option<PathBuf>,
    },
    /// Show WeChat process and account status
    Status,
    /// Show all managed file paths with existence status
    Paths {
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Check prerequisites for key extraction
    Doctor {
        /// Output fix commands for failing checks
        #[arg(long)]
        fix: bool,
    },
    /// Query decrypted WeChat databases (dev/debug tool)
    #[command(name = "db-dev", hide = true)]
    DbDev {
        /// Path to decrypted db_storage directory (containing contact/, session/, message/)
        #[arg(long)]
        path: PathBuf,

        #[command(subcommand)]
        action: DbDevAction,
    },
}

#[derive(Subcommand)]
pub enum DbDevAction {
    /// Query contacts
    Contacts {
        /// Search keyword (matches userName, alias, remark, nickName, description, phone, labels, signature, region)
        #[arg(long)]
        keyword: Option<String>,
        /// Maximum number of results (default: 1000, max: 20000)
        #[arg(long, default_value = "0")]
        limit: usize,
        /// Pagination offset
        #[arg(long, default_value = "0")]
        offset: usize,
    },
    /// Query recent sessions (conversations)
    Sessions {
        /// Maximum number of results
        #[arg(long, default_value = "0")]
        limit: usize,
        /// Pagination offset
        #[arg(long, default_value = "0")]
        offset: usize,
    },
    /// Query messages for a specific conversation
    Messages {
        /// Talker wxid or chatroom ID
        #[arg(long)]
        talker: String,
        /// Start time filter (Unix seconds, inclusive)
        #[arg(long)]
        start: Option<i64>,
        /// End time filter (Unix seconds, inclusive)
        #[arg(long)]
        end: Option<i64>,
        /// Content keyword filter (case-insensitive)
        #[arg(long)]
        keyword: Option<String>,
        /// Maximum number of results
        #[arg(long, default_value = "0")]
        limit: usize,
        /// Pagination offset
        #[arg(long, default_value = "0")]
        offset: usize,
    },
    /// Query chatrooms (group chats)
    Chatrooms {
        /// Filter by specific chatroom username
        #[arg(long)]
        username: Option<String>,
        /// Maximum number of results
        #[arg(long, default_value = "0")]
        limit: usize,
        /// Pagination offset
        #[arg(long, default_value = "0")]
        offset: usize,
    },
}

#[derive(Subcommand)]
pub enum MediaAction {
    /// Decrypt .dat image file(s) (XOR/V1/V2). Accepts a file or directory.
    #[command(name = "decrypt-dat")]
    DecryptDat {
        /// Input .dat file or directory of .dat files
        input: PathBuf,
        /// Output file or directory (auto-named if omitted)
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// V2 AES key (16-byte ASCII string); auto-read from KeyStore if omitted
        #[arg(long)]
        v2_key: Option<String>,
        /// Account directory name for KeyStore V2 key lookup (used when --v2-key is omitted)
        #[arg(long)]
        account: Option<String>,
        /// WeChat account data directory for automatic V2 key derivation (MD5(UIN+WXID))
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// XOR key for V2 tail (hex byte, e.g. "37"); auto-detected from thumbnails if omitted
        #[arg(long)]
        xor_key: Option<String>,
    },
    /// Resolve media path from hardlink.db
    #[command(name = "resolve-path")]
    ResolvePath {
        /// Path to hardlink.db
        #[arg(long)]
        db: PathBuf,
        /// Media type: image, video, file
        #[arg(long, default_value = "image")]
        media_type: String,
        /// MD5 key or file name prefix
        key: String,
    },
    /// Extract voice BLOB from media_N.db
    #[command(name = "extract-voice")]
    ExtractVoice {
        /// Path to media/ directory containing media_*.db files
        #[arg(long)]
        media_dir: PathBuf,
        /// Server ID (svr_id) of the voice message
        svr_id: String,
        /// Output file path
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Output raw SILK instead of transcoding to MP3
        #[arg(long)]
        raw: bool,
    },
    /// Decrypt WeChat Channels encrypted video using Isaac64 PRNG
    #[command(name = "decrypt-video")]
    DecryptVideo {
        /// Path to encrypted video file
        input: PathBuf,
        /// Decryption seed (decimal or hex with 0x prefix)
        #[arg(long)]
        seed: String,
        /// Output file path (default: <input>.mp4)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

#[derive(Clone, Debug, ValueEnum)]
pub enum OutputFormat {
    Text,
    Json,
}

#[derive(Clone, ValueEnum)]
pub enum ExportFormat {
    Txt,
    Json,
}

#[derive(Clone, ValueEnum)]
pub enum SortOrderArg {
    Asc,
    Desc,
}

impl From<SortOrderArg> for wx_db::SortOrder {
    fn from(v: SortOrderArg) -> Self {
        match v {
            SortOrderArg::Asc => wx_db::SortOrder::Asc,
            SortOrderArg::Desc => wx_db::SortOrder::Desc,
        }
    }
}

#[derive(Subcommand)]
enum KeyAction {
    /// Extract keys using the platform-native capture method
    Extract {
        /// Timeout in seconds for dynamic key capture
        #[arg(long, default_value = "120")]
        timeout: u64,
    },
    /// List stored keys
    List,
    /// Manually set a key for an account
    Set {
        /// Account directory name as stored in KeyStore (e.g. wxid_xxx_ab12, testuser001_1662)
        account: String,
        /// 32-byte hex key
        hex_key: String,
    },
    /// Manually set V2 image AES key for an account
    #[command(name = "set-image")]
    SetImage {
        /// Account directory name as stored in KeyStore (e.g. wxid_xxx_ab12, testuser001_1662)
        account: String,
        /// 16-byte image AES key (ASCII string or hex)
        image_key: String,
    },
    /// Scan WeChat process memory for pre-derived encryption keys
    Scan,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .init();

    let matches = Cli::command()
        .version(version::cli_version_long())
        .long_version(version::cli_version_long())
        .get_matches();
    let cli = Cli::from_arg_matches(&matches).unwrap();

    let result = match cli.command {
        Commands::Key { action } => match action {
            KeyAction::Extract { timeout: t } => cmd::key::cmd_key_extract(t).await,
            KeyAction::List => cmd::key::cmd_key_list(),
            KeyAction::Set { account, hex_key } => cmd::key::cmd_key_set(&account, &hex_key),
            KeyAction::SetImage { account, image_key } => {
                cmd::key::cmd_key_set_image(&account, &image_key)
            }
            KeyAction::Scan => cmd::key::cmd_key_scan(),
        },
        Commands::Media { action } => cmd::media::cmd_media(action),
        Commands::Watch {
            key,
            data_dir,
            account,
            poll,
            fsnotify,
            poll_ms,
            format,
            show_hidden,
        } => {
            cmd::watch::cmd_watch(
                key,
                data_dir,
                account,
                poll,
                fsnotify,
                poll_ms,
                format,
                show_hidden,
            )
            .await
        }
        Commands::Server { action } => cmd::server::cmd_server(action).await,
        Commands::Decrypt {
            key,
            data_dir,
            account,
            output,
            incremental,
        } => cmd::decrypt::cmd_decrypt(key, data_dir, account, output, incremental),
        Commands::Info { db_file } => cmd::info::cmd_info(&db_file),
        Commands::Sessions {
            data_dir,
            account,
            key,
            limit,
            offset,
            order,
            all,
            format,
            show_hidden,
            server,
        } => cmd::sessions::cmd_sessions(
            data_dir,
            account,
            key,
            limit,
            offset,
            order,
            all,
            format,
            show_hidden,
            server.into(),
        ),
        Commands::Contacts {
            data_dir,
            account,
            key,
            search,
            limit,
            offset,
            all,
            format,
            show_hidden,
            server,
        } => cmd::contacts::cmd_contacts(
            data_dir,
            account,
            key,
            search,
            limit,
            offset,
            all,
            format,
            show_hidden,
            server.into(),
        ),
        Commands::Query {
            contact,
            data_dir,
            account,
            key,
            since,
            until,
            msg_type,
            limit,
            offset,
            order,
            all,
            format,
            around_sort_seq,
            around_server_id,
            context,
            after_sort_seq,
            show_hidden,
            server,
        } => cmd::query::cmd_query(
            &contact,
            data_dir,
            account,
            key,
            since,
            until,
            msg_type,
            limit,
            offset,
            order,
            all,
            format,
            around_sort_seq,
            around_server_id,
            context,
            after_sort_seq,
            show_hidden,
            server.into(),
        ),
        Commands::Export {
            contact,
            output,
            data_dir,
            account,
            key,
            since,
            until,
            limit,
            offset,
            order,
            all,
            format,
            no_media,
            show_emoji,
            show_hidden,
            parallel,
        } => cmd::export::cmd_export(
            &contact,
            output,
            data_dir,
            account,
            key,
            since,
            until,
            limit,
            offset,
            order,
            all,
            format,
            no_media,
            show_emoji,
            show_hidden,
            parallel,
        ),
        Commands::Search {
            keyword,
            data_dir,
            account,
            key,
            limit,
            offset,
            all,
            format,
            server,
        } => cmd::search::cmd_search(
            &keyword,
            data_dir,
            account,
            key,
            limit,
            offset,
            all,
            format,
            server.into(),
        ),
        Commands::DecodeImage {
            input,
            output,
            account,
            data_dir,
        } => cmd::decode_image::cmd_decode_image(input, output, account, data_dir),
        Commands::Status => cmd::status::cmd_status(),
        Commands::Paths { json } => cmd::paths::cmd_paths(json),
        Commands::Doctor { fix } => cmd::doctor::cmd_doctor(fix),
        Commands::DbDev { path, action } => cmd::db_dev::cmd_db_dev(&path, action),
    };

    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
