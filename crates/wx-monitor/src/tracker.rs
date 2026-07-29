use std::collections::HashMap;

use wx_db::Session;

use crate::event::{SessionEvent, SessionEventKind};

/// Pure diff logic for detecting session changes.
///
/// Maintains a snapshot of `(username → sort_timestamp)` and compares
/// incoming session lists to emit change events.
pub(crate) struct SessionTracker {
    snapshot: HashMap<String, i64>,
}

impl SessionTracker {
    pub fn new() -> Self {
        Self {
            snapshot: HashMap::new(),
        }
    }

    /// Compare current sessions against the stored snapshot.
    ///
    /// Emits `Updated` for sessions that are new or have a newer `sort_timestamp`.
    pub fn diff(&mut self, sessions: &[Session]) -> Vec<SessionEvent> {
        let now = now_secs();
        let mut events = Vec::new();

        for s in sessions {
            let is_new_or_updated = match self.snapshot.get(&s.username) {
                None => true,
                Some(&old_ts) => s.sort_timestamp > old_ts,
            };

            if is_new_or_updated {
                events.push(SessionEvent {
                    username: s.username.clone(),
                    sort_timestamp: s.sort_timestamp,
                    detected_at: now,
                    kind: SessionEventKind::Updated,
                    summary: s.summary.clone(),
                    last_msg_type: s.last_msg_type,
                    last_msg_sender: s.last_msg_sender.clone(),
                    last_sender_display_name: s.last_sender_display_name.clone(),
                });
            }
        }

        // Update snapshot with all entries
        for s in sessions {
            self.snapshot.insert(s.username.clone(), s.sort_timestamp);
        }

        events
    }
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session(username: &str, ts: i64) -> Session {
        Session {
            username: username.to_string(),
            summary: String::new(),
            sort_timestamp: ts,
            last_msg_type: None,
            last_msg_sender: None,
            last_sender_display_name: None,
        }
    }

    #[test]
    fn diff_new_session_emits_updated() {
        let mut tracker = SessionTracker::new();
        let events = tracker.diff(&[session("alice", 100)]);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].username, "alice");
        assert!(matches!(events[0].kind, SessionEventKind::Updated));
    }

    #[test]
    fn diff_updated_timestamp_emits_updated() {
        let mut tracker = SessionTracker::new();
        tracker.diff(&[session("alice", 100)]);

        let events = tracker.diff(&[session("alice", 200)]);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].username, "alice");
        assert_eq!(events[0].sort_timestamp, 200);
    }

    #[test]
    fn diff_unchanged_emits_nothing() {
        let mut tracker = SessionTracker::new();
        tracker.diff(&[session("alice", 100)]);

        let events = tracker.diff(&[session("alice", 100)]);
        assert!(events.is_empty());
    }

    #[test]
    fn diff_carries_content_fields() {
        let mut tracker = SessionTracker::new();
        let s = Session {
            username: "wxid_alice".to_string(),
            summary: "hello world".to_string(),
            sort_timestamp: 100,
            last_msg_type: Some(1),
            last_msg_sender: Some("wxid_sender".to_string()),
            last_sender_display_name: Some("Sender Name".to_string()),
        };
        let events = tracker.diff(&[s]);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].summary, "hello world");
        assert_eq!(events[0].last_msg_type, Some(1));
        assert_eq!(events[0].last_msg_sender.as_deref(), Some("wxid_sender"));
        assert_eq!(
            events[0].last_sender_display_name.as_deref(),
            Some("Sender Name")
        );
    }
}
