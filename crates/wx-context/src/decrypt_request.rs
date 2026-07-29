use crate::cache::PersistentCache;
use crate::decrypt_scope::DecryptScope;
use crate::progress::{DecryptProgress, DecryptStats};
use crate::ContextError;

/// Fluent builder for scoped decryption requests.
pub struct DecryptRequest {
    scope: DecryptScope,
}

impl Default for DecryptRequest {
    fn default() -> Self {
        Self::new()
    }
}

impl DecryptRequest {
    /// Start with `All` scope (decrypt everything).
    pub fn new() -> Self {
        Self {
            scope: DecryptScope::All,
        }
    }

    /// Restrict to core DBs only (contact + session).
    pub fn core(mut self) -> Self {
        self.scope = DecryptScope::Core;
        self
    }

    /// Explicitly request all DBs.
    pub fn all(mut self) -> Self {
        self.scope = DecryptScope::All;
        self
    }

    /// Add specific message shards (implies core).
    pub fn shards(mut self, shard_ids: &[u32]) -> Self {
        self.scope = self.scope.with_shards(shard_ids.to_vec());
        self
    }

    /// Execute the decrypt request.
    pub fn execute(self, cache: &PersistentCache) -> Result<DecryptStats, ContextError> {
        cache.ensure_decrypted_scoped(&self.scope, |_| {})
    }

    /// Execute with progress callback.
    pub fn execute_with_progress(
        self,
        cache: &PersistentCache,
        on_progress: impl Fn(DecryptProgress) + Send + Sync,
    ) -> Result<DecryptStats, ContextError> {
        cache.ensure_decrypted_scoped(&self.scope, on_progress)
    }
}
