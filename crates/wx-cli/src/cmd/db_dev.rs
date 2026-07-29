use crate::DbDevAction;

pub fn cmd_db_dev(
    path: &std::path::Path,
    action: DbDevAction,
) -> Result<(), Box<dyn std::error::Error>> {
    let db = wx_db::WechatDb::open(path)?;

    match action {
        DbDevAction::Contacts {
            keyword,
            limit,
            offset,
        } => {
            let mut q = wx_db::ContactQuery::new().limit(limit).offset(offset);
            if let Some(kw) = keyword {
                q = q.keyword(kw);
            }
            let result = db.query_contacts(&q)?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        DbDevAction::Sessions { limit, offset } => {
            let result =
                db.query_sessions(&wx_db::SessionQuery::new().limit(limit).offset(offset))?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        DbDevAction::Messages {
            talker,
            start,
            end,
            keyword,
            limit,
            offset,
        } => {
            let mut q = wx_db::MessageQuery::for_talker(talker)
                .limit(limit)
                .offset(offset);
            if let Some(s) = start {
                q = q.since(s);
            }
            if let Some(e) = end {
                q = q.until(e);
            }
            if let Some(kw) = keyword {
                q = q.keyword(kw);
            }
            let result = db.query_messages(&q)?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        DbDevAction::Chatrooms {
            username,
            limit,
            offset,
        } => {
            let mut q = wx_db::ChatRoomQuery::new().limit(limit).offset(offset);
            if let Some(name) = username {
                q = q.username(name);
            }
            let result = db.query_chatrooms(&q)?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
    }

    Ok(())
}
