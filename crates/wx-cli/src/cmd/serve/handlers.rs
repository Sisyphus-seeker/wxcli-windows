use std::convert::Infallible;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Query, Request, State};
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::IntoResponse;
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;

use crate::cmd::server::types::{RuntimeAccountState, ServerHealthPayload};
use crate::output::{JsonEnvelope, PagingMeta, StatsMeta};
use crate::schema::{
    enrich_message, enrich_message_as_hit, enrich_native_fts_hit, enrich_session,
    project_message_items,
};
use crate::visibility_projection::{project_contacts_envelope, project_sessions_envelope_enriched};

use super::error::ServeError;
use super::event::SseEvent;
use super::media::{self, MediaRequest};
use super::state::AppState;

fn default_limit() -> usize {
    20
}

fn default_order() -> String {
    "desc".to_string()
}

fn parse_order(s: &str) -> wx_db::SortOrder {
    match s.to_lowercase().as_str() {
        "asc" => wx_db::SortOrder::Asc,
        _ => wx_db::SortOrder::Desc,
    }
}

pub async fn handler_health(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, ServeError> {
    Ok(Json(ServerHealthPayload {
        ready: state.ready.load(Ordering::Acquire),
        worker_id: state.worker_id.clone(),
        cli_version: state.cli_version.clone(),
        current_account: RuntimeAccountState {
            wxid: state.current_account.wxid.clone(),
            name: state.current_account.name.clone(),
        },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn health_payload_can_include_current_account_metadata() {
        let payload = serde_json::to_value(ServerHealthPayload {
            ready: true,
            worker_id: "worker-123".to_string(),
            cli_version: "1.2.3 (abc1234 2026-03-25)".to_string(),
            current_account: RuntimeAccountState {
                wxid: "wxid_me".to_string(),
                name: "Me".to_string(),
            },
        })
        .unwrap();

        assert_eq!(payload.get("ready"), Some(&Value::Bool(true)));
        assert_eq!(
            payload.get("worker_id"),
            Some(&Value::String("worker-123".to_string()))
        );
        assert_eq!(
            payload.get("cli_version"),
            Some(&Value::String("1.2.3 (abc1234 2026-03-25)".to_string()))
        );
        assert_eq!(
            payload.get("current_account").and_then(Value::as_object),
            Some(&serde_json::Map::from_iter([
                ("wxid".to_string(), Value::String("wxid_me".to_string())),
                ("name".to_string(), Value::String("Me".to_string())),
            ]))
        );
    }

    fn timeline_params(since: Option<i64>, until: Option<i64>) -> TimelineParams {
        TimelineParams {
            since,
            until,
            limit: 20,
            offset: 0,
            msg_type: None,
            order: "asc".to_string(),
            show_hidden: None,
        }
    }

    #[test]
    fn timeline_requires_a_bounded_time_range() {
        assert!(timeline_bounds(&timeline_params(None, Some(20))).is_err());
        assert!(timeline_bounds(&timeline_params(Some(10), None)).is_err());
        assert!(timeline_bounds(&timeline_params(Some(20), Some(10))).is_err());
        match timeline_bounds(&timeline_params(Some(10), Some(20))) {
            Ok(bounds) => assert_eq!(bounds, (10, 20)),
            Err(_) => panic!("valid timeline bounds should be accepted"),
        }
    }

    fn timeline_message(create_time: i64) -> TimelineMessage {
        TimelineMessage {
            sort_seq: create_time,
            server_id: create_time,
            msg_type: 1,
            sub_type: 0,
            sender: "wxid_other".to_string(),
            talker: "wxid_other".to_string(),
            talker_display_name: "Other".to_string(),
            create_time,
            status: 0,
            sender_display_name: "Other".to_string(),
            direction: wx_context::Direction::detect("wxid_other", "wxid_me"),
            snippet: create_time.to_string(),
        }
    }

    #[test]
    fn timeline_candidate_trimming_keeps_requested_edge() {
        let source = [5, 1, 3, 2, 4]
            .into_iter()
            .map(timeline_message)
            .collect::<Vec<_>>();

        let mut asc = source.clone();
        trim_timeline_candidates(&mut asc, wx_db::SortOrder::Asc, 2, false);
        assert_eq!(
            asc.iter().map(|item| item.create_time).collect::<Vec<_>>(),
            vec![1, 2]
        );

        let mut desc = source;
        trim_timeline_candidates(&mut desc, wx_db::SortOrder::Desc, 2, false);
        assert_eq!(
            desc.iter().map(|item| item.create_time).collect::<Vec<_>>(),
            vec![5, 4]
        );
    }
}

#[derive(Deserialize)]
pub struct MediaParams {
    server_id: Option<i64>,
    talker: Option<String>,
    format: Option<String>,
}

pub async fn handler_media(
    State(state): State<Arc<AppState>>,
    Query(params): Query<MediaParams>,
    request: Request,
) -> Result<axum::response::Response, ServeError> {
    let server_id = params
        .server_id
        .ok_or_else(|| ServeError::InvalidParam("missing required parameter: server_id".into()))?;
    let talker = params
        .talker
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| ServeError::InvalidParam("missing required parameter: talker".into()))?;
    let format = media::MediaFormat::parse(params.format.as_deref())?;

    media::serve_media(
        state,
        MediaRequest {
            server_id,
            talker,
            format,
        },
        request,
    )
    .await
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct SessionParams {
    #[serde(default = "default_limit")]
    limit: usize,
    #[serde(default)]
    offset: usize,
    #[serde(default = "default_order")]
    order: String,
    show_hidden: Option<String>,
}

pub async fn handler_sessions(
    State(state): State<Arc<AppState>>,
    Query(params): Query<SessionParams>,
) -> Result<impl IntoResponse, ServeError> {
    let db = Arc::clone(&state.db);
    let resolver = Arc::clone(&state.resolver);
    let visibility = Arc::clone(&state.visibility);
    let self_wxid = state.self_wxid.clone();
    let limit = wx_db::effective_limit(params.limit);
    let offset = params.offset;
    let order = parse_order(&params.order);
    let show_hidden = matches!(params.show_hidden.as_deref(), Some("1") | Some("true"));

    let result = tokio::task::spawn_blocking(move || {
        let guard = db.lock().map_err(|e| ServeError::Internal(e.to_string()))?;
        let result = guard
            .query_sessions(
                &wx_db::SessionQuery::new()
                    .limit(wx_db::MAX_QUERY_LIMIT)
                    .offset(0)
                    .order(order),
            )
            .map_err(|e| ServeError::Db(e.to_string()))?;

        let envelope = JsonEnvelope::from_query_result(result, limit, offset, |s| {
            enrich_session(s, &self_wxid, &resolver, None)
        });
        Ok::<_, ServeError>(project_sessions_envelope_enriched(
            envelope.items,
            &visibility,
            limit,
            offset,
            &envelope.stats,
            show_hidden,
        ))
    })
    .await
    .map_err(|e| ServeError::Internal(e.to_string()))??;

    Ok(Json(result))
}

// ---------------------------------------------------------------------------
// Contacts
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct ContactParams {
    search: Option<String>,
    #[serde(default = "default_limit")]
    limit: usize,
    #[serde(default)]
    offset: usize,
    show_hidden: Option<String>,
}

pub async fn handler_contacts(
    State(state): State<Arc<AppState>>,
    Query(params): Query<ContactParams>,
) -> Result<impl IntoResponse, ServeError> {
    let db = Arc::clone(&state.db);
    let visibility = Arc::clone(&state.visibility);
    let limit = wx_db::effective_limit(params.limit);
    let offset = params.offset;
    let search = params.search;
    let show_hidden = matches!(params.show_hidden.as_deref(), Some("1") | Some("true"));

    let result = tokio::task::spawn_blocking(move || {
        let guard = db.lock().map_err(|e| ServeError::Internal(e.to_string()))?;
        let mut query = wx_db::ContactQuery::new()
            .limit(wx_db::MAX_QUERY_LIMIT)
            .offset(0);
        if let Some(kw) = &search {
            query = query.keyword(kw);
        }
        let result = guard
            .query_contacts(&query)
            .map_err(|e| ServeError::Db(e.to_string()))?;

        let envelope = JsonEnvelope::from_query_result(result, wx_db::MAX_QUERY_LIMIT, 0, |c| c);
        Ok::<_, ServeError>(project_contacts_envelope(
            envelope.items,
            &visibility,
            limit,
            offset,
            &envelope.stats,
            show_hidden,
        ))
    })
    .await
    .map_err(|e| ServeError::Internal(e.to_string()))??;

    Ok(Json(result))
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct MessageParams {
    pub contact: Option<String>,
    #[serde(default = "default_limit")]
    pub limit: usize,
    #[serde(default)]
    pub offset: usize,
    pub since: Option<i64>,
    pub until: Option<i64>,
    #[serde(rename = "type")]
    pub msg_type: Option<String>,
    #[serde(default = "default_order")]
    pub order: String,
    pub around_sort_seq: Option<i64>,
    pub around_server_id: Option<i64>,
    pub context: Option<usize>,
    pub after_sort_seq: Option<i64>,
    pub show_hidden: Option<String>,
}

pub async fn handler_messages(
    State(state): State<Arc<AppState>>,
    Query(params): Query<MessageParams>,
) -> Result<impl IntoResponse, ServeError> {
    let contact = params
        .contact
        .ok_or_else(|| ServeError::InvalidParam("missing required parameter: contact".into()))?;

    // Anchor mutual exclusion validation
    let anchor_count = [
        params.around_sort_seq.is_some(),
        params.around_server_id.is_some(),
        params.after_sort_seq.is_some(),
    ]
    .iter()
    .filter(|&&b| b)
    .count();
    if anchor_count > 1 {
        return Err(ServeError::InvalidParam(
            "around_sort_seq, around_server_id, and after_sort_seq are mutually exclusive".into(),
        ));
    }
    let has_anchor = anchor_count == 1;

    // Anchor vs time-range mutual exclusion
    if has_anchor && (params.since.is_some() || params.until.is_some()) {
        return Err(ServeError::InvalidParam(
            "anchor parameters cannot be combined with since/until".into(),
        ));
    }

    // Offset must be 0 in anchor mode
    if has_anchor && params.offset != 0 {
        return Err(ServeError::InvalidParam(
            "offset is not supported with anchor queries".into(),
        ));
    }

    let db = Arc::clone(&state.db);
    let resolver = Arc::clone(&state.resolver);
    let visibility = Arc::clone(&state.visibility);
    let self_wxid = state.self_wxid.clone();
    let limit = wx_db::effective_limit(params.limit);
    let offset = params.offset;
    let order = parse_order(&params.order);
    let contact = contact.clone();
    let since = params.since;
    let until = params.until;
    let msg_type = params.msg_type.clone();
    let around_sort_seq = params.around_sort_seq;
    let around_server_id = params.around_server_id;
    let after_sort_seq = params.after_sort_seq;
    let context = params.context;
    let show_hidden = matches!(params.show_hidden.as_deref(), Some("1") | Some("true"));

    let result = tokio::task::spawn_blocking(move || {
        let guard = db.lock().map_err(|e| ServeError::Internal(e.to_string()))?;

        // Resolve contact — support wxid direct pass-through and fuzzy match
        let talker = resolve_contact(&contact, &resolver, &guard, Some(&visibility), show_hidden)?;

        let result = if has_anchor {
            let mut query = wx_db::MessageQuery::for_talker(&talker);

            if let Some(seq) = around_sort_seq {
                query = query.around_sort_seq(seq);
            } else if let Some(id) = around_server_id {
                query = query.around_server_id(id);
            } else if let Some(seq) = after_sort_seq {
                query = query.after_sort_seq(seq).limit(limit);
            }

            let has_around = around_sort_seq.is_some() || around_server_id.is_some();
            if has_around {
                if let Some(ctx) = context {
                    query = query.context(ctx);
                }
            }

            if let Some(ref t) = msg_type {
                if let Some(type_val) = wx_db::parse_msg_type(t) {
                    query = query.msg_type(type_val);
                }
            }

            guard
                .query_messages_anchor(&query)
                .map_err(|e| ServeError::Db(e.to_string()))?
        } else {
            let mut query = wx_db::MessageQuery::for_talker(&talker)
                .limit(limit)
                .offset(offset)
                .order(order);
            if let Some(s) = since {
                query = query.since(s);
            }
            if let Some(u) = until {
                query = query.until(u);
            }
            if let Some(ref t) = msg_type {
                if let Some(type_val) = wx_db::parse_msg_type(t) {
                    query = query.msg_type(type_val);
                }
            }

            guard
                .query_messages(&query)
                .map_err(|e| ServeError::Db(e.to_string()))?
        };

        let mut envelope = JsonEnvelope::from_message_query_result(result, limit, offset, |m| {
            enrich_message(m, &self_wxid, &resolver)
        });

        // When limit pushdown was used (non-anchor), total_rows only reflects the
        // scanned window. Use a lightweight COUNT(*) query for accurate DB-level total.
        if !has_anchor {
            let mt_filter = msg_type.as_ref().and_then(|s| wx_db::parse_msg_type(s));
            let db_total = guard.count_messages(
                &talker,
                since.unwrap_or(0),
                until.unwrap_or(i64::MAX),
                mt_filter,
            );
            envelope.paging.total = db_total;
            envelope.paging.has_more = offset + envelope.paging.returned < db_total;
        }

        // Phase 2: sender-level projection
        let projected = project_message_items(envelope.items, &talker, &visibility, show_hidden);
        envelope.paging.returned = projected.len();
        envelope.items = projected;

        Ok::<_, ServeError>(envelope)
    })
    .await
    .map_err(|e| ServeError::Internal(e.to_string()))??;

    Ok(Json(result))
}

// ---------------------------------------------------------------------------
// Timeline — messages across every conversation in one bounded query
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct TimelineParams {
    pub since: Option<i64>,
    pub until: Option<i64>,
    #[serde(default = "default_limit")]
    pub limit: usize,
    #[serde(default)]
    pub offset: usize,
    #[serde(rename = "type")]
    pub msg_type: Option<String>,
    #[serde(default = "default_order")]
    pub order: String,
    pub show_hidden: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct TimelineMessage {
    pub sort_seq: i64,
    pub server_id: i64,
    pub msg_type: u32,
    pub sub_type: u32,
    pub sender: String,
    pub talker: String,
    pub talker_display_name: String,
    pub create_time: i64,
    pub status: i32,
    pub sender_display_name: String,
    pub direction: wx_context::Direction,
    pub snippet: String,
}

impl TimelineMessage {
    fn from_enriched(message: crate::schema::EnrichedMessage, talker_display_name: String) -> Self {
        let crate::schema::EnrichedMessage {
            message,
            sender_display_name,
            direction,
            snippet,
            ..
        } = message;
        Self {
            sort_seq: message.sort_seq,
            server_id: message.server_id,
            msg_type: message.msg_type,
            sub_type: message.sub_type,
            sender: message.sender,
            talker: message.talker,
            talker_display_name,
            create_time: message.create_time,
            status: message.status,
            sender_display_name,
            direction,
            snippet,
        }
    }
}

fn sort_timeline_messages(messages: &mut [TimelineMessage], order: wx_db::SortOrder) {
    match order {
        wx_db::SortOrder::Asc => {
            messages.sort_unstable_by_key(|item| (item.create_time, item.sort_seq, item.server_id))
        }
        wx_db::SortOrder::Desc => messages.sort_unstable_by(|a, b| {
            (b.create_time, b.sort_seq, b.server_id).cmp(&(a.create_time, a.sort_seq, a.server_id))
        }),
    }
}

fn trim_timeline_candidates(
    messages: &mut Vec<TimelineMessage>,
    order: wx_db::SortOrder,
    keep_limit: usize,
    force: bool,
) {
    if force || messages.len() > keep_limit.saturating_mul(2) {
        sort_timeline_messages(messages, order);
        messages.truncate(keep_limit);
    }
}

fn timeline_bounds(params: &TimelineParams) -> Result<(i64, i64), ServeError> {
    let since = params
        .since
        .ok_or_else(|| ServeError::InvalidParam("missing required parameter: since".into()))?;
    let until = params
        .until
        .ok_or_else(|| ServeError::InvalidParam("missing required parameter: until".into()))?;
    if since > until {
        return Err(ServeError::InvalidParam(
            "since must be less than or equal to until".into(),
        ));
    }
    Ok((since, until))
}

/// Read a time-bounded timeline across all conversations in one server request.
///
/// This is intentionally implemented inside the warm server process. Agent memory jobs and
/// archive tools no longer need to launch one CLI process and make one HTTP round-trip for every
/// active conversation.
pub async fn handler_timeline(
    State(state): State<Arc<AppState>>,
    Query(params): Query<TimelineParams>,
) -> Result<impl IntoResponse, ServeError> {
    let (since, until) = timeline_bounds(&params)?;
    let db = Arc::clone(&state.db);
    let resolver = Arc::clone(&state.resolver);
    let visibility = Arc::clone(&state.visibility);
    let self_wxid = state.self_wxid.clone();
    let limit = wx_db::effective_limit(params.limit);
    let offset = params.offset;
    let keep_limit = offset.saturating_add(limit);
    let order = parse_order(&params.order);
    let msg_type = params.msg_type.as_deref().and_then(wx_db::parse_msg_type);
    let show_hidden = matches!(params.show_hidden.as_deref(), Some("1") | Some("true"));

    let result = tokio::task::spawn_blocking(move || {
        let guard = db.lock().map_err(|e| ServeError::Internal(e.to_string()))?;
        let sessions = guard
            .query_sessions(
                &wx_db::SessionQuery::new()
                    .limit(wx_db::MAX_QUERY_LIMIT)
                    .offset(0),
            )
            .map_err(|e| ServeError::Db(e.to_string()))?;

        let mut messages = Vec::new();
        let mut total = 0usize;
        let mut scanned = 0usize;
        let mut skipped = sessions.stats.skipped;
        let mut shard_warnings = Vec::new();

        for session in sessions.items {
            let talker = session.username;
            if !show_hidden && visibility.is_hidden_talker(&talker) {
                continue;
            }

            let talker_display_name = resolver.display_with_id(&talker);
            let mut talker_offset = 0usize;

            loop {
                let mut query = wx_db::MessageQuery::for_talker(&talker)
                    .since(since)
                    .until(until)
                    .limit(wx_db::MAX_QUERY_LIMIT)
                    .offset(talker_offset)
                    .order(order);
                if let Some(mt) = msg_type {
                    query = query.msg_type(mt);
                }

                let page = guard
                    .query_messages(&query)
                    .map_err(|e| ServeError::Db(e.to_string()))?;
                let returned = page.items.len();
                scanned = scanned.saturating_add(page.stats.total_rows);
                skipped = skipped.saturating_add(page.stats.skipped);
                shard_warnings.extend(page.shard_warnings);

                let enriched = page
                    .items
                    .into_iter()
                    .map(|message| enrich_message(message, &self_wxid, &resolver))
                    .collect();
                let projected = project_message_items(enriched, &talker, &visibility, show_hidden);
                total = total.saturating_add(projected.len());
                messages.extend(projected.into_iter().map(|message| {
                    TimelineMessage::from_enriched(message, talker_display_name.clone())
                }));

                // Retain only the global candidates needed for this page. The common first-page
                // path now stays close to 2×limit instead of holding the entire history in memory.
                trim_timeline_candidates(&mut messages, order, keep_limit, false);

                if returned < wx_db::MAX_QUERY_LIMIT {
                    break;
                }
                talker_offset = talker_offset.saturating_add(returned);
            }
        }

        trim_timeline_candidates(&mut messages, order, keep_limit, true);
        let start = offset.min(total);
        let items: Vec<_> = messages.into_iter().skip(start).take(limit).collect();
        let returned = items.len();

        Ok::<_, ServeError>(JsonEnvelope {
            items,
            paging: PagingMeta {
                limit,
                offset,
                returned,
                has_more: start + returned < total,
                total,
            },
            stats: StatsMeta {
                scanned,
                skipped,
                elapsed_ms: None,
                shard_warnings,
            },
        })
    })
    .await
    .map_err(|e| ServeError::Internal(e.to_string()))??;

    Ok(Json(result))
}

// ---------------------------------------------------------------------------
// Search
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct SearchParams {
    q: Option<String>,
    #[serde(default = "default_limit")]
    limit: usize,
    #[serde(default)]
    offset: usize,
}

pub async fn handler_search(
    State(state): State<Arc<AppState>>,
    Query(params): Query<SearchParams>,
) -> Result<impl IntoResponse, ServeError> {
    let search_start = std::time::Instant::now();
    let q = params
        .q
        .ok_or_else(|| ServeError::InvalidParam("missing required parameter: q".into()))?;
    let resolver = Arc::clone(&state.resolver);
    let self_wxid = state.self_wxid.clone();
    let limit = wx_db::effective_limit(params.limit);
    let offset = params.offset;

    // Phase 1: Try native FTS using the independent connection (NO main DB lock).
    let fts_conn = state.fts_conn.clone();
    let q_clone = q.clone();
    let resolver_clone = Arc::clone(&resolver);
    let self_wxid_clone = self_wxid.clone();
    let state_arc = Arc::clone(&state);

    let native_result: Option<Result<JsonEnvelope<_>, ServeError>> = if let Some(fts_mutex) =
        fts_conn
    {
        let result = tokio::task::spawn_blocking(move || {
            let fts_guard = fts_mutex
                .lock()
                .map_err(|e: std::sync::PoisonError<_>| ServeError::Internal(e.to_string()))?;
            // Lazy-init name2id cache with proper error propagation.
            let name2id = {
                let mut cache_guard = state_arc
                    .name2id_cache
                    .lock()
                    .map_err(|e: std::sync::PoisonError<_>| ServeError::Internal(e.to_string()))?;
                match cache_guard.as_ref() {
                    Some(map) => map.clone(),
                    None => {
                        let loaded = wx_db::native_fts::load_name2id(&fts_guard)
                            .map_err(|e| ServeError::Db(e.to_string()))?;
                        *cache_guard = Some(loaded.clone());
                        loaded
                    }
                }
            };
            match wx_db::native_fts::search_message_fts_with_cache(
                &fts_guard,
                &q_clone,
                limit,
                offset,
                Some(&name2id),
            ) {
                Ok(result) => {
                    let total = result.total_hits;
                    let items: Vec<_> = result
                        .hits
                        .into_iter()
                        .map(|hit| enrich_native_fts_hit(hit, &self_wxid_clone, &resolver_clone))
                        .collect();
                    let returned = items.len();
                    let has_more = offset + returned < total;
                    Ok(JsonEnvelope {
                        items,
                        paging: crate::output::PagingMeta {
                            limit,
                            offset,
                            returned,
                            has_more,
                            total,
                        },
                        stats: crate::output::StatsMeta {
                            scanned: 0,
                            skipped: 0,
                            elapsed_ms: Some(search_start.elapsed().as_millis() as u64),
                            shard_warnings: Vec::new(),
                        },
                    })
                }
                Err(e) => {
                    eprintln!("warn: native FTS search failed, falling back to scan: {e}");
                    Err(ServeError::Internal("fts_failed".into()))
                }
            }
        })
        .await
        .map_err(|e| ServeError::Internal(e.to_string()))?;

        match result {
            Ok(envelope) => Some(Ok(envelope)),
            Err(_) => None, // Fall through to scan
        }
    } else {
        None
    };

    if let Some(Ok(envelope)) = native_result {
        return Ok(Json(envelope));
    }

    // Phase 2: Scan fallback — requires main DB lock.
    let db = Arc::clone(&state.db);
    let result = tokio::task::spawn_blocking(move || {
        let mut guard = db.lock().map_err(|e| ServeError::Internal(e.to_string()))?;

        // Try native FTS first using pooled connection.
        // On failure: reopen FTS connection and retry once before falling back to scan.
        let native_result: Option<wx_db::NativeFtsResult> = {
            let first_attempt = guard
                .pool()
                .and_then(|pool| pool.fts_conn())
                .map(|fts_conn| wx_db::native_fts::search_message_fts(fts_conn, &q, limit, offset));

            match first_attempt {
                Some(Ok(r)) => Some(r),
                Some(Err(e)) => {
                    // FTS query failed — attempt reopen + retry
                    eprintln!("warn: native FTS search failed, attempting reopen: {e}");
                    match guard.reopen_fts() {
                        Ok(()) => {
                            // Reopen succeeded — retry query with fresh connection
                            guard
                                .pool()
                                .and_then(|pool| pool.fts_conn())
                                .and_then(|fts_conn| {
                                    match wx_db::native_fts::search_message_fts(
                                        fts_conn, &q, limit, offset,
                                    ) {
                                        Ok(r) => Some(r),
                                        Err(e2) => {
                                            eprintln!(
                                                "warn: native FTS search failed after reopen, \
                                                 falling back to scan: {e2}"
                                            );
                                            None
                                        }
                                    }
                                })
                        }
                        Err(reopen_err) => {
                            eprintln!(
                                "warn: FTS reopen failed, falling back to scan: {reopen_err}"
                            );
                            None
                        }
                    }
                }
                // No pool or no fts_conn — skip directly to scan fallback
                None => None,
            }
        };

        let (hits, total_hits, scan_scanned, scan_skipped, shard_warnings): (
            Vec<_>,
            usize,
            usize,
            usize,
            Vec<wx_db::ShardWarning>,
        ) = match native_result {
            Some(result) => {
                let total = result.total_hits;
                let items = result
                    .hits
                    .into_iter()
                    .map(|hit| enrich_native_fts_hit(hit, &self_wxid, &resolver))
                    .collect();
                (items, total, 0, 0, Vec::new())
            }
            None => {
                // Scan fallback: iterate all sessions and search by keyword.
                let mut all_sessions = Vec::new();
                let page_size = wx_db::MAX_QUERY_LIMIT;
                let mut sess_offset = 0;
                loop {
                    let page = guard
                        .query_sessions(
                            &wx_db::SessionQuery::new()
                                .limit(page_size)
                                .offset(sess_offset),
                        )
                        .map_err(|e| ServeError::Db(e.to_string()))?;
                    if page.items.is_empty() {
                        break;
                    }
                    let done = sess_offset + page.items.len() >= page.stats.total_rows;
                    sess_offset += page.items.len();
                    all_sessions.extend(page.items);
                    if done {
                        break;
                    }
                }

                let mut all_hits: Vec<(wx_db::Message, String)> = Vec::new();
                let mut total_scanned: usize = 0;
                let mut total_skipped: usize = 0;
                let mut all_shard_warnings: Vec<wx_db::ShardWarning> = Vec::new();
                for session in &all_sessions {
                    let result = guard
                        .query_messages(
                            &wx_db::MessageQuery::for_talker(&session.username)
                                .keyword(&q)
                                .limit(wx_db::MAX_QUERY_LIMIT),
                        )
                        .map_err(|e| ServeError::Db(e.to_string()))?;
                    total_scanned += result.stats.total_rows;
                    total_skipped += result.stats.skipped;
                    all_shard_warnings.extend(result.shard_warnings);
                    for msg in result.items {
                        all_hits.push((msg, session.username.clone()));
                    }
                }

                // Sort by (sort_seq DESC, create_time DESC, server_id DESC)
                all_hits.sort_by(|a, b| {
                    b.0.sort_seq
                        .cmp(&a.0.sort_seq)
                        .then_with(|| b.0.create_time.cmp(&a.0.create_time))
                        .then_with(|| b.0.server_id.cmp(&a.0.server_id))
                });

                let total = all_hits.len();
                let page: Vec<_> = all_hits.into_iter().skip(offset).take(limit).collect();
                let enriched: Vec<_> = page
                    .into_iter()
                    .map(|(m, talker)| enrich_message_as_hit(m, talker, &self_wxid, &resolver))
                    .collect();
                (
                    enriched,
                    total,
                    total_scanned,
                    total_skipped,
                    all_shard_warnings,
                )
            }
        };

        let returned = hits.len();
        let has_more = offset + returned < total_hits;
        let envelope = JsonEnvelope {
            items: hits,
            paging: crate::output::PagingMeta {
                limit,
                offset,
                returned,
                has_more,
                total: total_hits,
            },
            stats: crate::output::StatsMeta {
                scanned: scan_scanned,
                skipped: scan_skipped,
                elapsed_ms: Some(search_start.elapsed().as_millis() as u64),
                shard_warnings,
            },
        };
        Ok::<_, ServeError>(envelope)
    })
    .await
    .map_err(|e| ServeError::Internal(e.to_string()))??;

    Ok(Json(result))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn resolve_contact(
    contact: &str,
    resolver: &wx_context::ContactResolver,
    db: &wx_db::WechatDb,
    visibility: Option<&wx_context::VisibilityIndex>,
    show_hidden: bool,
) -> Result<String, ServeError> {
    use crate::contact_id::{resolve_contact_id, ContactResolveError};

    match resolve_contact_id(contact, resolver, db, visibility, show_hidden) {
        Ok(resolved) => Ok(resolved.wxid),
        Err(ContactResolveError::NotFound(msg)) | Err(ContactResolveError::Hidden(msg)) => {
            Err(ServeError::InvalidParam(msg))
        }
        Err(ContactResolveError::Ambiguous(msg)) => Err(ServeError::InvalidParam(msg)),
    }
}

// ---------------------------------------------------------------------------
// SSE
// ---------------------------------------------------------------------------

pub async fn handler_sse(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    if !state.ready.load(Ordering::Acquire) {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error": "bridge initializing, SSE not ready"})),
        )
            .into_response();
    }

    let rx = state.broadcast_tx.subscribe();
    let shutdown = state.shutdown.clone();
    let base = BroadcastStream::new(rx).filter_map(|result| match result {
        Ok(event) => {
            let json = serde_json::to_string(event.as_ref()).ok()?;
            let event_type = match event.as_ref() {
                SseEvent::Session(_) => "session",
                SseEvent::Message(_) => "message",
                SseEvent::Heartbeat => "heartbeat",
            };
            Some(Ok::<_, Infallible>(
                Event::default().event(event_type).data(json),
            ))
        }
        Err(_) => None, // Lagged — skip
    });
    let stream = futures_util::StreamExt::take_until(base, shutdown.cancelled_owned());
    Sse::new(stream)
        .keep_alive(KeepAlive::new().interval(Duration::from_secs(30)))
        .into_response()
}
