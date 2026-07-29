use dashmap::DashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// Per-file mutex map to prevent concurrent `ensure_decrypted` calls
/// from operating on the same DB file simultaneously.
#[derive(Default)]
pub(crate) struct FileLockMap {
    inner: DashMap<PathBuf, Arc<Mutex<()>>>,
}

impl FileLockMap {
    /// Returns an `Arc<Mutex<()>>` for the given path.
    ///
    /// Callers should `.lock().unwrap()` on the returned Arc in their own
    /// scope — never while holding a DashMap entry reference.
    pub fn lock_for(&self, path: &Path) -> Arc<Mutex<()>> {
        self.inner
            .entry(path.to_path_buf())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc as StdArc;

    #[test]
    fn same_path_returns_same_mutex() {
        let map = FileLockMap::default();
        let path = Path::new("/tmp/test.db");

        let a = map.lock_for(path);
        let b = map.lock_for(path);

        assert!(StdArc::ptr_eq(&a, &b));
    }

    #[test]
    fn different_paths_do_not_block_each_other() {
        let map = StdArc::new(FileLockMap::default());
        let path_a = PathBuf::from("/tmp/a.db");
        let path_b = PathBuf::from("/tmp/b.db");

        let lock_a = map.lock_for(&path_a);
        let _guard_a = lock_a.lock().unwrap();

        // Locking a different path must succeed immediately (not blocked by path_a).
        let lock_b = map.lock_for(&path_b);
        let result = lock_b.try_lock();
        assert!(
            result.is_ok(),
            "lock on different path should not be blocked"
        );
    }
}
