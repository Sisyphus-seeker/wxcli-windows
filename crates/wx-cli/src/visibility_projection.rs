use wx_context::VisibilityIndex;
use wx_db::Contact;

use crate::output::{JsonEnvelope, PagingMeta, StatsMeta};
use crate::schema::{project_session_sender, EnrichedSession};

/// Filter a fully collected result set, then rebuild paging metadata for the visible slice.
///
/// Phase 1 uses this only on relatively small list-shaped outputs (`contacts` / `sessions`),
/// where loading the current matched result set into memory is acceptable.
pub fn project_visible_envelope<T>(
    items: Vec<T>,
    limit: usize,
    offset: usize,
    stats: &StatsMeta,
    show_hidden: bool,
    should_hide: impl Fn(&T) -> bool,
) -> JsonEnvelope<T> {
    let visible: Vec<T> = if show_hidden {
        items
    } else {
        items
            .into_iter()
            .filter(|item| !should_hide(item))
            .collect()
    };

    let total = visible.len();
    let start = offset.min(total);
    let paged: Vec<T> = visible.into_iter().skip(start).take(limit).collect();
    let returned = paged.len();
    let has_more = start + returned < total;

    JsonEnvelope {
        items: paged,
        paging: PagingMeta {
            limit,
            offset,
            returned,
            has_more,
            total,
        },
        stats: StatsMeta {
            scanned: stats.scanned,
            skipped: stats.skipped,
            elapsed_ms: stats.elapsed_ms,
            shard_warnings: stats.shard_warnings.clone(),
        },
    }
}

pub fn project_contacts_envelope(
    contacts: Vec<Contact>,
    visibility: &VisibilityIndex,
    limit: usize,
    offset: usize,
    stats: &StatsMeta,
    show_hidden: bool,
) -> JsonEnvelope<Contact> {
    project_visible_envelope(contacts, limit, offset, stats, show_hidden, |contact| {
        visibility.is_hidden_talker(&contact.user_name)
    })
}

#[allow(dead_code)]
pub fn project_sessions_envelope<T>(
    sessions: Vec<T>,
    visibility: &VisibilityIndex,
    limit: usize,
    offset: usize,
    stats: &StatsMeta,
    show_hidden: bool,
    talker_of: impl Fn(&T) -> &str,
) -> JsonEnvelope<T> {
    project_visible_envelope(sessions, limit, offset, stats, show_hidden, |session| {
        visibility.is_hidden_talker(talker_of(session))
    })
}

/// Phase 2: project_sessions_envelope with sender-level redaction for EnrichedSession.
///
/// After talker-level filtering, applies `project_session_sender` to redact
/// hidden senders in group chat session summaries.
pub fn project_sessions_envelope_enriched(
    sessions: Vec<EnrichedSession>,
    visibility: &VisibilityIndex,
    limit: usize,
    offset: usize,
    stats: &StatsMeta,
    show_hidden: bool,
) -> JsonEnvelope<EnrichedSession> {
    let mut envelope = project_visible_envelope(
        sessions,
        limit,
        offset,
        stats,
        show_hidden,
        |session: &EnrichedSession| visibility.is_hidden_talker(&session.session.username),
    );

    if !show_hidden {
        for session in &mut envelope.items {
            project_session_sender(session, visibility);
        }
    }

    envelope
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stats_meta(scanned: usize) -> StatsMeta {
        StatsMeta {
            scanned,
            skipped: 0,
            elapsed_ms: Some(1),
            shard_warnings: Vec::new(),
        }
    }

    #[test]
    fn visible_projection_rebuilds_total_and_offset_on_filtered_set() {
        let envelope = project_visible_envelope(
            vec!["wxid_a", "wxid_hidden", "wxid_b"],
            1,
            1,
            &stats_meta(3),
            false,
            |talker| *talker == "wxid_hidden",
        );

        assert_eq!(envelope.items, vec!["wxid_b"]);
        assert_eq!(envelope.paging.total, 2);
        assert_eq!(envelope.paging.returned, 1);
        assert_eq!(envelope.paging.offset, 1);
        assert!(!envelope.paging.has_more);
        assert_eq!(envelope.stats.scanned, 3);
    }

    #[test]
    fn show_hidden_bypasses_filtering() {
        let envelope = project_visible_envelope(
            vec!["wxid_a", "wxid_hidden", "wxid_b"],
            3,
            0,
            &stats_meta(3),
            true,
            |talker| *talker == "wxid_hidden",
        );

        assert_eq!(envelope.items, vec!["wxid_a", "wxid_hidden", "wxid_b"]);
        assert_eq!(envelope.paging.total, 3);
        assert_eq!(envelope.paging.returned, 3);
        assert!(!envelope.paging.has_more);
    }
}
