use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};

use crate::error::MonitorError;
use crate::event::{FileEvent, FileEventKind};

pub(crate) trait FileWatcher: Send + 'static {
    fn watch(&mut self, path: &Path) -> Result<(), MonitorError>;
}

// ---------------------------------------------------------------------------
// NotifyWatcher
// ---------------------------------------------------------------------------

pub(crate) struct NotifyWatcher {
    inner: RecommendedWatcher,
}

impl NotifyWatcher {
    pub fn new(tx: Sender<FileEvent>) -> Result<Self, MonitorError> {
        let watcher = RecommendedWatcher::new(
            move |res: Result<notify::Event, notify::Error>| match res {
                Ok(event) => {
                    let kind = match event.kind {
                        EventKind::Create(_) => FileEventKind::Created,
                        EventKind::Modify(_) => FileEventKind::Modified,
                        EventKind::Remove(_) => {
                            tracing::debug!(event_kind = ?event.kind, paths = ?event.paths, "remove event, treating as Modified");
                            FileEventKind::Modified
                        }
                        _ => {
                            tracing::debug!(event_kind = ?event.kind, paths = ?event.paths, "ignoring event");
                            return;
                        }
                    };
                    tracing::debug!(event_kind = ?event.kind, paths = ?event.paths, "file event received");
                    for path in event.paths {
                        let _ = tx.send(FileEvent {
                            path,
                            kind: match kind {
                                FileEventKind::Created => FileEventKind::Created,
                                FileEventKind::Modified => FileEventKind::Modified,
                            },
                        });
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "notify watcher error");
                }
            },
            notify::Config::default(),
        )?;
        Ok(Self { inner: watcher })
    }
}

impl FileWatcher for NotifyWatcher {
    fn watch(&mut self, path: &Path) -> Result<(), MonitorError> {
        tracing::info!(path = %path.display(), "notify watcher: watching path");
        self.inner.watch(path, RecursiveMode::NonRecursive)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// PollingWatcher
// ---------------------------------------------------------------------------

pub(crate) struct PollingWatcher {
    interval: Duration,
    tx: Sender<FileEvent>,
    shutdown: Arc<AtomicBool>,
    paths: Arc<Mutex<HashMap<PathBuf, Option<SystemTime>>>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl PollingWatcher {
    pub fn new(interval: Duration, tx: Sender<FileEvent>, shutdown: Arc<AtomicBool>) -> Self {
        Self {
            interval,
            tx,
            shutdown,
            paths: Arc::new(Mutex::new(HashMap::new())),
            thread: None,
        }
    }

    fn ensure_thread(&mut self) {
        if self.thread.is_some() {
            return;
        }

        let interval = self.interval;
        let tx = self.tx.clone();
        let shutdown = self.shutdown.clone();
        let paths = self.paths.clone();

        let handle = std::thread::spawn(move || loop {
            if shutdown.load(Ordering::Relaxed) {
                break;
            }
            std::thread::sleep(interval);
            if shutdown.load(Ordering::Relaxed) {
                break;
            }

            tracing::trace!("polling cycle");
            let mut tracked = paths.lock().unwrap();
            for (path, prev_mtime) in tracked.iter_mut() {
                let current = std::fs::metadata(path).ok().and_then(|m| m.modified().ok());

                match (prev_mtime.as_ref(), current) {
                    (None, Some(mtime)) => {
                        *prev_mtime = Some(mtime);
                        tracing::debug!(path = %path.display(), "file created");
                        let _ = tx.send(FileEvent {
                            path: path.clone(),
                            kind: FileEventKind::Created,
                        });
                    }
                    (Some(old), Some(new)) if new > *old => {
                        tracing::debug!(path = %path.display(), old_mtime = ?old, new_mtime = ?new, "file modified");
                        *prev_mtime = Some(new);
                        let _ = tx.send(FileEvent {
                            path: path.clone(),
                            kind: FileEventKind::Modified,
                        });
                    }
                    (Some(_), None) => {
                        *prev_mtime = None;
                    }
                    _ => {}
                }
            }
        });

        self.thread = Some(handle);
    }
}

impl FileWatcher for PollingWatcher {
    fn watch(&mut self, path: &Path) -> Result<(), MonitorError> {
        let initial_mtime = std::fs::metadata(path).ok().and_then(|m| m.modified().ok());
        tracing::info!(path = %path.display(), initial_mtime = ?initial_mtime, "polling watcher: watching path");

        self.paths
            .lock()
            .unwrap()
            .insert(path.to_path_buf(), initial_mtime);

        self.ensure_thread();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    #[test]
    fn polling_watcher_detects_modification() {
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("test.db");
        std::fs::write(&file, b"initial").unwrap();

        std::thread::sleep(Duration::from_millis(50));

        let (tx, rx) = mpsc::channel();
        let shutdown = Arc::new(AtomicBool::new(false));

        let mut watcher = PollingWatcher::new(Duration::from_millis(100), tx, shutdown.clone());
        watcher.watch(&file).unwrap();

        std::thread::sleep(Duration::from_millis(50));
        std::fs::write(&file, b"modified content").unwrap();

        let event = rx.recv_timeout(Duration::from_secs(3)).unwrap();
        assert_eq!(event.path, file);
        assert!(matches!(event.kind, FileEventKind::Modified));

        shutdown.store(true, Ordering::Relaxed);
    }

    #[test]
    fn polling_watcher_detects_creation() {
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("new.db-wal");

        let (tx, rx) = mpsc::channel();
        let shutdown = Arc::new(AtomicBool::new(false));

        let mut watcher = PollingWatcher::new(Duration::from_millis(100), tx, shutdown.clone());
        watcher.watch(&file).unwrap();

        std::thread::sleep(Duration::from_millis(50));
        std::fs::write(&file, b"wal data").unwrap();

        let event = rx.recv_timeout(Duration::from_secs(3)).unwrap();
        assert_eq!(event.path, file);
        assert!(matches!(event.kind, FileEventKind::Created));

        shutdown.store(true, Ordering::Relaxed);
    }

    #[test]
    fn polling_watcher_tracks_paths_added_after_thread_start() {
        let dir = tempfile::TempDir::new().unwrap();
        let file1 = dir.path().join("session.db");
        let file2 = dir.path().join("session.db-wal");
        std::fs::write(&file1, b"db initial").unwrap();

        let (tx, rx) = mpsc::channel();
        let shutdown = Arc::new(AtomicBool::new(false));

        let mut watcher = PollingWatcher::new(Duration::from_millis(100), tx, shutdown.clone());

        // First watch starts the thread
        watcher.watch(&file1).unwrap();
        // Second watch adds path after thread is running
        watcher.watch(&file2).unwrap();

        std::thread::sleep(Duration::from_millis(50));

        // Modify the second file (added after thread start)
        std::fs::write(&file2, b"wal data").unwrap();

        let event = rx.recv_timeout(Duration::from_secs(3)).unwrap();
        assert_eq!(event.path, file2);
        assert!(matches!(event.kind, FileEventKind::Created));

        shutdown.store(true, Ordering::Relaxed);
    }

    #[test]
    #[ignore] // FSEvents on macOS temp dirs can be slow/flaky in CI
    fn notify_watcher_detects_modification() {
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("test.db");
        std::fs::write(&file, b"initial").unwrap();

        let (tx, rx) = mpsc::channel();

        let mut watcher = NotifyWatcher::new(tx).unwrap();
        watcher.watch(dir.path()).unwrap();

        std::thread::sleep(Duration::from_millis(200));
        std::fs::write(&file, b"modified").unwrap();

        let event = rx.recv_timeout(Duration::from_secs(3)).unwrap();
        let expected = file.canonicalize().unwrap();
        let actual = event.path.canonicalize().unwrap();
        assert_eq!(actual, expected);
    }
}
