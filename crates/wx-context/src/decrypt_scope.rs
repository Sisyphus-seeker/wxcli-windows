use std::collections::HashSet;

use crate::db_category::{DbCategory, DbFile};

/// Which databases to decrypt.
#[derive(Debug, Clone)]
pub enum DecryptScope {
    /// Decrypt everything.
    All,
    /// Only contact.db + session.db.
    Core,
    /// Arbitrary set of categories.
    Categories(HashSet<DbCategory>),
    /// Core DBs + specific message shards.
    MessageShards { shard_ids: Vec<u32> },
}

impl DecryptScope {
    /// Convenience: core-only scope.
    pub fn core() -> Self {
        Self::Core
    }

    /// Upgrade to include specific message shards (implies Core).
    pub fn with_shards(self, shard_ids: Vec<u32>) -> Self {
        Self::MessageShards { shard_ids }
    }

    /// Check whether a given DB file is included in this scope.
    pub fn matches(&self, db: &DbFile) -> bool {
        match self {
            Self::All => true,
            Self::Core => matches!(db.category, DbCategory::Contact | DbCategory::Session),
            Self::Categories(cats) => cats.contains(&db.category),
            Self::MessageShards { shard_ids } => match &db.category {
                DbCategory::Contact | DbCategory::Session => true,
                DbCategory::MessageShard { shard_id } => shard_ids.contains(shard_id),
                _ => false,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn db(name: &str) -> DbFile {
        DbFile::categorize(PathBuf::from(format!("/tmp/{name}.db")))
    }

    #[test]
    fn all_matches_everything() {
        let scope = DecryptScope::All;
        assert!(scope.matches(&db("contact")));
        assert!(scope.matches(&db("session")));
        assert!(scope.matches(&db("message_0")));
        assert!(scope.matches(&db("message_fts")));
        assert!(scope.matches(&db("other")));
    }

    #[test]
    fn core_matches_only_contact_and_session() {
        let scope = DecryptScope::core();
        assert!(scope.matches(&db("contact")));
        assert!(scope.matches(&db("session")));
        assert!(!scope.matches(&db("message_0")));
        assert!(!scope.matches(&db("message_fts")));
        assert!(!scope.matches(&db("other")));
    }

    #[test]
    fn message_shards_includes_core_and_selected() {
        let scope = DecryptScope::core().with_shards(vec![0, 2]);
        assert!(scope.matches(&db("contact")));
        assert!(scope.matches(&db("session")));
        assert!(scope.matches(&db("message_0")));
        assert!(!scope.matches(&db("message_1")));
        assert!(scope.matches(&db("message_2")));
        assert!(!scope.matches(&db("message_fts")));
    }

    #[test]
    fn categories_matches_specified() {
        let mut cats = HashSet::new();
        cats.insert(DbCategory::Fts);
        cats.insert(DbCategory::Contact);
        let scope = DecryptScope::Categories(cats);
        assert!(scope.matches(&db("contact")));
        assert!(scope.matches(&db("message_fts")));
        assert!(!scope.matches(&db("session")));
        assert!(!scope.matches(&db("message_0")));
    }
}
