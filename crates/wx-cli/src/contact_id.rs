use wx_context::{ContactResolver, VisibilityIndex};
use wx_db::is_group_chat;

/// Result of contact resolution: the canonical wxid and optional display name.
#[derive(Debug)]
pub struct ResolvedContact {
    pub wxid: String,
    pub display_name: Option<String>,
}

/// Errors from contact resolution.
#[derive(Debug)]
pub enum ContactResolveError {
    NotFound(String),
    Ambiguous(String),
    Hidden(String),
}

impl std::fmt::Display for ContactResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound(s) | Self::Ambiguous(s) | Self::Hidden(s) => f.write_str(s),
        }
    }
}

/// Shared contact/session identifier resolver used by `query`, `serve`, and `export`.
///
/// Precedence:
/// 1. Unambiguous special identifiers: `wxid_*`, `*@chatroom`, `filehelper`
/// 2. Exact username match in ContactResolver
/// 3. Conservative legacy-ID short-circuit for account-like ASCII identifiers
///    (requires digit; prevents fuzzy mis-resolution of bare account IDs)
/// 4. Fuzzy match via ContactResolver (`find_candidates`)
/// 5. DB keyword fallback
///
/// When `visibility` is provided and `show_hidden` is false, hidden talkers
/// are rejected with `ContactResolveError::Hidden` without leaking existence.
pub fn resolve_contact_id(
    contact: &str,
    resolver: &ContactResolver,
    db: &wx_db::WechatDb,
    visibility: Option<&VisibilityIndex>,
    show_hidden: bool,
) -> Result<ResolvedContact, ContactResolveError> {
    // 0. Empty / whitespace-only guard
    if contact.trim().is_empty() {
        return Err(ContactResolveError::NotFound(
            "empty contact identifier".to_string(),
        ));
    }

    // 1. Unambiguous special identifiers
    if contact.starts_with("wxid_") || is_group_chat(contact) || contact == "filehelper" {
        let resolved = ResolvedContact {
            wxid: contact.to_string(),
            display_name: None,
        };
        return check_visibility(resolved, visibility, show_hidden);
    }

    // 2. Exact username match (covers legacy IDs like "testuser001" that exist as contact usernames)
    if let Some(display) = resolver.resolve(contact) {
        let resolved = ResolvedContact {
            wxid: contact.to_string(),
            display_name: Some(display.to_string()),
        };
        return check_visibility(resolved, visibility, show_hidden);
    }

    // 3. Conservative legacy-ID short-circuit: ASCII alphanumeric + underscore with at least
    //    one digit (e.g. "testuser001"). This prevents fuzzy matching from mis-resolving a bare
    //    account ID to an unrelated contact whose display name happens to substring-match.
    //    Pure-alpha names like "Alice" and hyphenated names like "team-alpha" are NOT matched.
    if is_account_like(contact) {
        let resolved = ResolvedContact {
            wxid: contact.to_string(),
            display_name: None,
        };
        return check_visibility(resolved, visibility, show_hidden);
    }

    // 4. Fuzzy match via ContactResolver
    let candidates = resolver.find_candidates(contact);
    match candidates.len() {
        1 => {
            let (name, wxid) = candidates[0];
            let resolved = ResolvedContact {
                wxid: wxid.to_string(),
                display_name: Some(name.to_string()),
            };
            return check_visibility(resolved, visibility, show_hidden);
        }
        n if n > 1 => {
            // Filter out hidden candidates before reporting ambiguity
            let visible: Vec<_> = if let Some(vis) = visibility {
                candidates
                    .into_iter()
                    .filter(|(_, wxid)| show_hidden || !vis.is_hidden_talker(wxid))
                    .collect()
            } else {
                candidates
            };
            match visible.len() {
                0 => {
                    return Err(ContactResolveError::NotFound(format!(
                        "contact \"{contact}\" not found"
                    )));
                }
                1 => {
                    let (name, wxid) = visible[0];
                    return Ok(ResolvedContact {
                        wxid: wxid.to_string(),
                        display_name: Some(name.to_string()),
                    });
                }
                _ => {
                    return Err(ContactResolveError::Ambiguous(format_ambiguous(
                        contact,
                        &visible
                            .iter()
                            .map(|(name, wxid)| (name.to_string(), wxid.to_string()))
                            .collect::<Vec<_>>(),
                    )));
                }
            }
        }
        _ => {}
    }

    // 5. DB keyword fallback
    let result = db
        .query_contacts(&wx_db::ContactQuery::new().keyword(contact).limit(10))
        .map_err(|e| ContactResolveError::NotFound(format!("db error: {e}")))?;

    // Filter hidden contacts from DB results
    let visible_items: Vec<_> = if let Some(vis) = visibility {
        result
            .items
            .into_iter()
            .filter(|c| show_hidden || !vis.is_hidden_talker(&c.user_name))
            .collect()
    } else {
        result.items
    };

    match visible_items.len() {
        1 => {
            let c = &visible_items[0];
            let name = if !c.remark.is_empty() {
                &c.remark
            } else if !c.nick_name.is_empty() {
                &c.nick_name
            } else {
                &c.user_name
            };
            Ok(ResolvedContact {
                wxid: c.user_name.clone(),
                display_name: Some(name.to_string()),
            })
        }
        0 => Err(ContactResolveError::NotFound(format!(
            "contact \"{contact}\" not found"
        ))),
        _ => Err(ContactResolveError::Ambiguous(format_ambiguous(
            contact,
            &visible_items
                .iter()
                .map(|c| {
                    let name = if !c.remark.is_empty() {
                        c.remark.clone()
                    } else {
                        c.nick_name.clone()
                    };
                    (name, c.user_name.clone())
                })
                .collect::<Vec<_>>(),
        ))),
    }
}

/// Check if a resolved contact is hidden. Returns the contact if visible,
/// or a generic "not found" error that does not leak hidden status.
fn check_visibility(
    resolved: ResolvedContact,
    visibility: Option<&VisibilityIndex>,
    show_hidden: bool,
) -> Result<ResolvedContact, ContactResolveError> {
    if let Some(vis) = visibility {
        if !show_hidden && vis.is_hidden_talker(&resolved.wxid) {
            return Err(ContactResolveError::Hidden(format!(
                "contact \"{}\" not found",
                resolved.wxid
            )));
        }
    }
    Ok(resolved)
}

/// Check if a string looks like a WeChat account-like identifier.
///
/// Conservative: requires pure ASCII alphanumeric + underscore, AND at least one digit.
/// The digit requirement avoids treating ASCII display names like "Alice" or "Bob"
/// as direct identifiers. Real account IDs virtually always contain digits
/// (e.g. `testuser001`, `user123456`).
fn is_account_like(s: &str) -> bool {
    !s.is_empty()
        && s.is_ascii()
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && s.chars().any(|c| c.is_ascii_digit())
}

fn format_ambiguous(contact: &str, items: &[(String, String)]) -> String {
    let mut msg = format!(
        "ambiguous contact \"{contact}\": {} matches found. Use wxid directly:\n",
        items.len()
    );
    for (name, wxid) in items {
        msg.push_str(&format!("  {name}（{wxid}）\n"));
    }
    msg
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_account_like_accepts_wxid_pattern() {
        assert!(is_account_like("wxid_example123abc"));
    }

    #[test]
    fn is_account_like_accepts_legacy_id() {
        assert!(is_account_like("testuser001"));
    }

    #[test]
    fn is_account_like_accepts_underscore_with_digits() {
        assert!(is_account_like("user_name_123"));
    }

    #[test]
    fn is_account_like_rejects_pure_alpha() {
        // "Alice", "Bob", "team" should NOT bypass fuzzy match
        assert!(!is_account_like("Alice"));
        assert!(!is_account_like("Bob"));
    }

    #[test]
    fn is_account_like_rejects_hyphen() {
        // Hyphens not in real account IDs
        assert!(!is_account_like("team-alpha"));
    }

    #[test]
    fn is_account_like_rejects_chinese() {
        assert!(!is_account_like("张三"));
    }

    #[test]
    fn is_account_like_rejects_spaces() {
        assert!(!is_account_like("John Doe"));
    }

    #[test]
    fn is_account_like_rejects_empty() {
        assert!(!is_account_like(""));
    }

    #[test]
    fn empty_contact_returns_error() {
        let resolver = ContactResolver::empty();
        let db = {
            let tmp = tempfile::tempdir().unwrap();
            create_minimal_db(tmp.path())
        };

        let err = resolve_contact_id("", &resolver, &db, None, false).unwrap_err();
        assert!(err.to_string().contains("empty contact identifier"));

        let err = resolve_contact_id("   ", &resolver, &db, None, false).unwrap_err();
        assert!(err.to_string().contains("empty contact identifier"));
    }

    #[test]
    fn direct_identifiers_pass_through() {
        let resolver = ContactResolver::empty();
        let db = {
            let tmp = tempfile::tempdir().unwrap();
            create_minimal_db(tmp.path())
        };

        let r = resolve_contact_id("wxid_abc", &resolver, &db, None, false).unwrap();
        assert_eq!(r.wxid, "wxid_abc");

        let r = resolve_contact_id("group@chatroom", &resolver, &db, None, false).unwrap();
        assert_eq!(r.wxid, "group@chatroom");

        let r = resolve_contact_id("filehelper", &resolver, &db, None, false).unwrap();
        assert_eq!(r.wxid, "filehelper");
    }

    #[test]
    fn legacy_ascii_id_passes_through() {
        let resolver = ContactResolver::empty();
        let db = {
            let tmp = tempfile::tempdir().unwrap();
            create_minimal_db(tmp.path())
        };

        let r = resolve_contact_id("testuser001", &resolver, &db, None, false).unwrap();
        assert_eq!(r.wxid, "testuser001");
    }

    #[test]
    fn exact_username_match_keeps_display_name_before_legacy_short_circuit() {
        let tmp = tempfile::tempdir().unwrap();
        let db = create_db_with_contacts(
            tmp.path(),
            &[
                ("testuser001", "", "小明", "xming"),
                ("wxid_other", "", "其他人", ""),
            ],
        );
        let resolver = ContactResolver::build(&db).unwrap();

        let r = resolve_contact_id("testuser001", &resolver, &db, None, false).unwrap();
        assert_eq!(r.wxid, "testuser001");
        assert_eq!(r.display_name.as_deref(), Some("小明"));
    }

    #[test]
    fn legacy_ascii_id_bypasses_fuzzy_resolution() {
        let tmp = tempfile::tempdir().unwrap();
        let db = create_db_with_contacts(
            tmp.path(),
            &[
                ("wxid_friend", "testuser001 的同学", "", ""),
                ("wxid_other", "其他人", "", ""),
            ],
        );
        let resolver = ContactResolver::build(&db).unwrap();

        let r = resolve_contact_id("testuser001", &resolver, &db, None, false).unwrap();
        assert_eq!(r.wxid, "testuser001");
        assert_eq!(r.display_name, None);
    }

    #[test]
    fn chinese_name_not_treated_as_direct_id() {
        let resolver = ContactResolver::empty();
        let db = {
            let tmp = tempfile::tempdir().unwrap();
            create_minimal_db(tmp.path())
        };

        // Chinese name should fall through to fuzzy/db lookup and fail as "not found"
        let result = resolve_contact_id("张三", &resolver, &db, None, false);
        assert!(result.is_err());
    }

    #[test]
    fn hidden_talker_returns_not_found() {
        let resolver = ContactResolver::empty();
        let db = {
            let tmp = tempfile::tempdir().unwrap();
            create_minimal_db(tmp.path())
        };
        let vis = VisibilityIndex::build(&["wxid_hidden".to_string()], &[], &resolver);

        let result = resolve_contact_id("wxid_hidden", &resolver, &db, Some(&vis), false);
        assert!(result.is_err());
        // Error should look like "not found", not leak "hidden"
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("not found"));
    }

    #[test]
    fn show_hidden_bypasses_visibility() {
        let resolver = ContactResolver::empty();
        let db = {
            let tmp = tempfile::tempdir().unwrap();
            create_minimal_db(tmp.path())
        };
        let vis = VisibilityIndex::build(&["wxid_hidden".to_string()], &[], &resolver);

        let r = resolve_contact_id("wxid_hidden", &resolver, &db, Some(&vis), true).unwrap();
        assert_eq!(r.wxid, "wxid_hidden");
    }

    #[test]
    fn hidden_talker_hidden_error_does_not_leak() {
        let resolver = ContactResolver::empty();
        let db = {
            let tmp = tempfile::tempdir().unwrap();
            create_minimal_db(tmp.path())
        };
        let vis = VisibilityIndex::build(&["wxid_secret".to_string()], &[], &resolver);

        let result = resolve_contact_id("wxid_secret", &resolver, &db, Some(&vis), false);
        let err = result.unwrap_err();
        // The error message should not contain the word "hidden"
        let msg = err.to_string();
        assert!(!msg.contains("hidden"), "error leaked visibility: {msg}");
        assert!(msg.contains("not found"));
    }

    fn create_minimal_db(dir: &std::path::Path) -> wx_db::WechatDb {
        let msg_dir = dir.join("message");
        std::fs::create_dir_all(&msg_dir).unwrap();
        let contact_dir = dir.join("contact");
        std::fs::create_dir_all(&contact_dir).unwrap();
        let session_dir = dir.join("session");
        std::fs::create_dir_all(&session_dir).unwrap();

        let msg_conn = rusqlite::Connection::open(msg_dir.join("message_0.db")).unwrap();
        msg_conn
            .execute_batch(
                "CREATE TABLE msg_0 (
                    localId INTEGER, mesSvrID INTEGER, msgCreateTime INTEGER, msgType INTEGER,
                    msgSubType INTEGER, msgSeq INTEGER, msgContent TEXT, msgSource TEXT,
                    msgStatus INTEGER, compressContent BLOB, mesMsgSender TEXT
                );",
            )
            .unwrap();

        let contact_conn = rusqlite::Connection::open(contact_dir.join("contact.db")).unwrap();
        contact_conn
            .execute_batch(
                "CREATE TABLE contact (
                    username TEXT PRIMARY KEY, alias TEXT DEFAULT '', remark TEXT DEFAULT '',
                    nick_name TEXT DEFAULT '', description TEXT DEFAULT NULL,
                    extra_buffer BLOB DEFAULT NULL
                );
                CREATE TABLE contact_label (
                    label_id_ TEXT, label_name_ TEXT, sort_order_ INTEGER
                );",
            )
            .unwrap();

        let session_conn = rusqlite::Connection::open(session_dir.join("session.db")).unwrap();
        session_conn
            .execute_batch(
                "CREATE TABLE SessionTable (
                    userName TEXT, summary TEXT, sortTimestamp INTEGER,
                    lastMsgType INTEGER, lastMsgSender TEXT, lastSenderDisplayName TEXT
                );",
            )
            .unwrap();

        wx_db::WechatDb::open(dir).unwrap()
    }

    fn create_db_with_contacts(
        dir: &std::path::Path,
        contacts: &[(&str, &str, &str, &str)],
    ) -> wx_db::WechatDb {
        let db = create_minimal_db(dir);
        let contact_db = dir.join("contact").join("contact.db");
        let conn = rusqlite::Connection::open(contact_db).unwrap();
        for (username, remark, nick_name, alias) in contacts {
            conn.execute(
                "INSERT INTO contact (username, remark, nick_name, alias) VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![username, remark, nick_name, alias],
            )
            .unwrap();
        }
        db
    }
}
