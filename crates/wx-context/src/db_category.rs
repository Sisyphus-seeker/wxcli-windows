use std::path::{Path, PathBuf};

/// Categorization of WeChat database files.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DbCategory {
    Contact,
    Session,
    MessageShard { shard_id: u32 },
    Fts,
    Other,
}

/// A database file with its path and category.
#[derive(Debug, Clone)]
pub struct DbFile {
    pub path: PathBuf,
    pub category: DbCategory,
}

impl DbFile {
    /// Categorize a database file by its stem.
    pub fn categorize(path: PathBuf) -> Self {
        let category = match path.file_stem().and_then(|s| s.to_str()) {
            Some("contact") => DbCategory::Contact,
            Some("session") => DbCategory::Session,
            Some("message_fts") => DbCategory::Fts,
            Some(stem) => {
                if let Some(suffix) = stem.strip_prefix("message_") {
                    if let Ok(id) = suffix.parse::<u32>() {
                        DbCategory::MessageShard { shard_id: id }
                    } else {
                        DbCategory::Other
                    }
                } else {
                    DbCategory::Other
                }
            }
            None => DbCategory::Other,
        };
        Self { path, category }
    }
}

/// Recursively discover and categorize all `.db` files under `dir`.
pub fn discover_db_files(dir: &Path) -> Result<Vec<DbFile>, std::io::Error> {
    let mut result = Vec::new();
    collect_db_files(dir, &mut result)?;
    result.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(result)
}

fn collect_db_files(dir: &Path, out: &mut Vec<DbFile>) -> Result<(), std::io::Error> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let ft = entry.file_type()?;
        if ft.is_dir() {
            collect_db_files(&entry.path(), out)?;
        } else if ft.is_file() && entry.path().extension().is_some_and(|e| e == "db") {
            out.push(DbFile::categorize(entry.path()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn categorize_contact() {
        let db = DbFile::categorize(PathBuf::from("/tmp/contact.db"));
        assert_eq!(db.category, DbCategory::Contact);
    }

    #[test]
    fn categorize_session() {
        let db = DbFile::categorize(PathBuf::from("/tmp/session.db"));
        assert_eq!(db.category, DbCategory::Session);
    }

    #[test]
    fn categorize_message_shard() {
        let db = DbFile::categorize(PathBuf::from("/tmp/message_0.db"));
        assert_eq!(db.category, DbCategory::MessageShard { shard_id: 0 });

        let db = DbFile::categorize(PathBuf::from("/tmp/message_42.db"));
        assert_eq!(db.category, DbCategory::MessageShard { shard_id: 42 });
    }

    #[test]
    fn categorize_fts() {
        let db = DbFile::categorize(PathBuf::from("/tmp/message_fts.db"));
        assert_eq!(db.category, DbCategory::Fts);
    }

    #[test]
    fn categorize_unknown() {
        let db = DbFile::categorize(PathBuf::from("/tmp/something_else.db"));
        assert_eq!(db.category, DbCategory::Other);
    }

    #[test]
    fn discover_db_files_with_temp_dir() {
        let tmp = TempDir::new().unwrap();
        let sub = tmp.path().join("contact");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(sub.join("contact.db"), b"").unwrap();
        std::fs::write(tmp.path().join("session.db"), b"").unwrap();
        std::fs::write(tmp.path().join("message_0.db"), b"").unwrap();
        std::fs::write(tmp.path().join("message_fts.db"), b"").unwrap();
        std::fs::write(tmp.path().join("not_a_db.txt"), b"").unwrap();

        let files = discover_db_files(tmp.path()).unwrap();
        assert_eq!(files.len(), 4);

        let categories: Vec<_> = files.iter().map(|f| &f.category).collect();
        assert!(categories.contains(&&DbCategory::Contact));
        assert!(categories.contains(&&DbCategory::Session));
        assert!(categories.contains(&&DbCategory::MessageShard { shard_id: 0 }));
        assert!(categories.contains(&&DbCategory::Fts));
    }
}
