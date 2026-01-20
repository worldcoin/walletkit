//! File-based storage lock for serializing writes.

use std::fs::{self, File, OpenOptions};
use std::path::Path;
use std::sync::Arc;

use fs2::FileExt;

use super::error::{StorageError, StorageResult};

/// A file-backed lock that serializes storage mutations across processes.
#[derive(Debug, Clone)]
pub struct StorageLock {
    file: Arc<File>,
}

impl StorageLock {
    /// Opens or creates the lock file at `path`.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be opened or created.
    pub fn open(path: &Path) -> StorageResult<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(map_io_err)?;
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(path)
            .map_err(map_io_err)?;
        Ok(Self {
            file: Arc::new(file),
        })
    }

    /// Acquires the exclusive lock.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock cannot be acquired.
    pub fn lock(&self) -> StorageResult<StorageLockGuard> {
        self.file.lock_exclusive().map_err(map_io_err)?;
        Ok(StorageLockGuard {
            file: Arc::clone(&self.file),
        })
    }
}

/// Guard that holds an exclusive lock for its lifetime.
#[derive(Debug)]
pub struct StorageLockGuard {
    file: Arc<File>,
}

impl Drop for StorageLockGuard {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

fn map_io_err(err: std::io::Error) -> StorageError {
    StorageError::Lock(err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn temp_lock_path() -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("walletkit-lock-{}.lock", Uuid::new_v4()));
        path
    }

    #[test]
    fn test_lock_is_exclusive() {
        let path = temp_lock_path();
        let lock_a = StorageLock::open(&path).expect("open lock");
        let _guard = lock_a.lock().expect("acquire lock");

        let lock_b = StorageLock::open(&path).expect("open lock");
        lock_b
            .file
            .try_lock_exclusive()
            .expect_err("lock should be held");

        drop(_guard);
        lock_b
            .file
            .try_lock_exclusive()
            .expect("lock available after release");
        lock_b.file.unlock().expect("unlock");

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn test_lock_serializes_across_threads() {
        let path = temp_lock_path();
        let lock = StorageLock::open(&path).expect("open lock");

        let (locked_tx, locked_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let (released_tx, released_rx) = std::sync::mpsc::channel();

        let lock_clone = lock.clone();
        let path_clone = path.clone();
        let thread_a = std::thread::spawn(move || {
            let _guard = lock_clone.lock().expect("lock in thread");
            locked_tx.send(()).expect("signal locked");
            release_rx.recv().expect("wait release");
            drop(_guard);
            released_tx.send(()).expect("signal released");
            let _ = std::fs::remove_file(path_clone);
        });

        locked_rx.recv().expect("wait locked");
        let lock_b = StorageLock::open(&path).expect("open lock");
        lock_b
            .file
            .try_lock_exclusive()
            .expect_err("lock should be held");

        release_tx.send(()).expect("release");
        released_rx.recv().expect("wait released");

        lock_b
            .file
            .try_lock_exclusive()
            .expect("lock available after release");
        lock_b.file.unlock().expect("unlock");

        thread_a.join().expect("thread join");
    }
}
