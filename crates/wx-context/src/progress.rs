use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

// ── Public types ──

#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecryptProgress {
    Starting { total: usize },
    Decrypting { path: String },
    Decrypted { path: String, wal_patched: bool },
    Skipped { path: String, wal_patched: bool },
    Failed { path: String, error: String },
}

pub struct DecryptStats {
    pub decrypted: usize,
    pub skipped: usize,
    pub errors: usize,
    pub wal_patched: usize,
    /// Non-fatal warnings (e.g. WAL decrypt failures) for the CLI to display.
    pub warnings: Vec<String>,
}

// ── Internal types ──

pub(crate) enum DbOutcome {
    Decrypted {
        wal_patched: bool,
        wal_warnings: Vec<String>,
    },
    Skipped {
        wal_patched: bool,
        wal_warnings: Vec<String>,
    },
    Failed {
        warning: String,
    },
}

#[derive(Debug)]
pub(crate) enum WalOutcome {
    Patched,
    NothingToDo,
    Warning(String),
}

pub(crate) struct AtomicStats {
    decrypted: AtomicUsize,
    skipped: AtomicUsize,
    errors: AtomicUsize,
    wal_patched: AtomicUsize,
    warnings: Mutex<Vec<String>>,
}

impl AtomicStats {
    pub(crate) fn new() -> Self {
        Self {
            decrypted: AtomicUsize::new(0),
            skipped: AtomicUsize::new(0),
            errors: AtomicUsize::new(0),
            wal_patched: AtomicUsize::new(0),
            warnings: Mutex::new(Vec::new()),
        }
    }

    pub(crate) fn inc_decrypted(&self) {
        self.decrypted.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn inc_skipped(&self) {
        self.skipped.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn inc_errors(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn inc_wal_patched(&self) {
        self.wal_patched.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn add_warning(&self, msg: String) {
        self.warnings.lock().unwrap().push(msg);
    }

    pub(crate) fn into_stats(self) -> DecryptStats {
        DecryptStats {
            decrypted: self.decrypted.into_inner(),
            skipped: self.skipped.into_inner(),
            errors: self.errors.into_inner(),
            wal_patched: self.wal_patched.into_inner(),
            warnings: self.warnings.into_inner().unwrap(),
        }
    }
}
