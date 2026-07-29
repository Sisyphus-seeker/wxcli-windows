use std::path::PathBuf;

use serde::Serialize;

/// Internal event from the file watcher layer.
#[derive(Debug)]
#[allow(dead_code)] // fields read in tests; monitor loop only checks event arrival
pub(crate) struct FileEvent {
    pub path: PathBuf,
    pub kind: FileEventKind,
}

/// Kind of file change detected.
#[derive(Debug)]
pub(crate) enum FileEventKind {
    Modified,
    Created,
}

/// A detected change in the WeChat session list.
#[derive(Debug, Clone, Serialize)]
pub struct SessionEvent {
    /// The wxid or chatroom username that changed.
    pub username: String,
    /// The sort_timestamp from session.db.
    pub sort_timestamp: i64,
    /// Unix timestamp (seconds) when the change was detected.
    pub detected_at: i64,
    /// Whether this is an incremental update or a full reset.
    pub kind: SessionEventKind,
    /// Summary text of the last message.
    pub summary: String,
    /// The message type of the last message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_msg_type: Option<u32>,
    /// The wxid of the last message sender.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_msg_sender: Option<String>,
    /// The display name of the last message sender.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_sender_display_name: Option<String>,
}

/// Kind of session change.
#[derive(Debug, Clone, Serialize)]
pub enum SessionEventKind {
    /// Session was updated (new or changed sort_timestamp).
    Updated,
}
