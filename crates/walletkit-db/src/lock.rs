//! Cross-process exclusive lock.
//!
//! Used by [`crate::init_or_open_envelope_key`] to serialize the first-install
//! envelope bootstrap, and acquired by consumers for operations that mix
//! `SQLite` with filesystem state (e.g. plaintext export / import). `SQLite`
//! handles cross-process writer serialization for ordinary mutations itself
//! via WAL-mode file locks; this lock is not required for those.
//!
//! On native platforms (Unix, Windows) the lock is backed by a file via
//! `flock` / `LockFileEx`. On WASM it is a no-op because the runtime is
//! single-threaded (`sqlite-wasm-rs` is compiled with `SQLITE_THREADSAFE=0`)
//! and runs in a dedicated Web Worker.

use std::path::Path;

use crate::error::StoreResult;

// WASM: no-op lock (single-threaded worker, SQLITE_THREADSAFE=0)

#[cfg(target_arch = "wasm32")]
mod imp {
    use super::*;

    /// No-op storage lock for WASM.
    #[derive(Debug, Clone)]
    pub struct Lock;

    /// No-op lock guard.
    #[derive(Debug)]
    pub struct LockGuard;

    impl Lock {
        /// Opens a no-op lock (WASM is single-threaded).
        pub fn open(_path: &Path) -> StoreResult<Self> {
            Ok(Self)
        }

        /// Acquires a no-op lock (always succeeds).
        pub fn lock(&self) -> StoreResult<LockGuard> {
            Ok(LockGuard)
        }

        /// Attempts to acquire a no-op lock (always succeeds).
        pub fn try_lock(&self) -> StoreResult<Option<LockGuard>> {
            Ok(Some(LockGuard))
        }
    }
}

// Native: file-backed exclusive lock (flock on Unix, LockFileEx on Windows)

#[cfg(not(target_arch = "wasm32"))]
mod imp {
    use super::{Path, StoreResult};
    use crate::error::StoreError;
    use std::fs::{self, File, OpenOptions};
    use std::sync::Arc;

    /// File-backed cross-process exclusive lock. See the module docs for
    /// what it's for (and what it isn't).
    #[derive(Debug, Clone)]
    pub struct Lock {
        file: Arc<File>,
    }

    /// Guard that holds an exclusive lock for its lifetime.
    #[derive(Debug)]
    pub struct LockGuard {
        file: Arc<File>,
    }

    impl Lock {
        /// Opens or creates the lock file at `path`.
        ///
        /// # Errors
        ///
        /// Returns an error if the file cannot be opened or created.
        pub fn open(path: &Path) -> StoreResult<Self> {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).map_err(|err| map_io_err(&err))?;
            }
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(path)
                .map_err(|err| map_io_err(&err))?;
            Ok(Self {
                file: Arc::new(file),
            })
        }

        /// Acquires the exclusive lock.
        ///
        /// # Errors
        ///
        /// Returns an error if the lock cannot be acquired.
        pub fn lock(&self) -> StoreResult<LockGuard> {
            lock_exclusive(&self.file).map_err(|err| map_io_err(&err))?;
            Ok(LockGuard {
                file: Arc::clone(&self.file),
            })
        }

        /// Attempts to acquire the exclusive lock without blocking.
        ///
        /// # Errors
        ///
        /// Returns an error if the lock attempt fails for reasons other than
        /// the lock being held by another process.
        pub fn try_lock(&self) -> StoreResult<Option<LockGuard>> {
            if try_lock_exclusive(&self.file).map_err(|err| map_io_err(&err))? {
                Ok(Some(LockGuard {
                    file: Arc::clone(&self.file),
                }))
            } else {
                Ok(None)
            }
        }
    }

    impl Drop for LockGuard {
        fn drop(&mut self) {
            let _ = unlock(&self.file);
        }
    }

    fn map_io_err(err: &std::io::Error) -> StoreError {
        StoreError::Lock(err.to_string())
    }

    // ── Unix flock ──────────────────────────────────────────────────────

    #[cfg(unix)]
    fn lock_exclusive(file: &File) -> std::io::Result<()> {
        let fd = std::os::unix::io::AsRawFd::as_raw_fd(file);
        let result = unsafe { flock(fd, LOCK_EX) };
        if result == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    #[cfg(unix)]
    fn try_lock_exclusive(file: &File) -> std::io::Result<bool> {
        let fd = std::os::unix::io::AsRawFd::as_raw_fd(file);
        let result = unsafe { flock(fd, LOCK_EX | LOCK_NB) };
        if result == 0 {
            Ok(true)
        } else {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::WouldBlock {
                Ok(false)
            } else {
                Err(err)
            }
        }
    }

    #[cfg(unix)]
    fn unlock(file: &File) -> std::io::Result<()> {
        let fd = std::os::unix::io::AsRawFd::as_raw_fd(file);
        let result = unsafe { flock(fd, LOCK_UN) };
        if result == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    #[cfg(unix)]
    use std::os::raw::c_int;

    #[cfg(unix)]
    const LOCK_EX: c_int = 2;
    #[cfg(unix)]
    const LOCK_NB: c_int = 4;
    #[cfg(unix)]
    const LOCK_UN: c_int = 8;

    #[cfg(unix)]
    extern "C" {
        fn flock(fd: c_int, operation: c_int) -> c_int;
    }

    // ── Windows LockFileEx ──────────────────────────────────────────────

    #[cfg(windows)]
    fn lock_exclusive(file: &File) -> std::io::Result<()> {
        lock_file(file, 0)
    }

    #[cfg(windows)]
    fn try_lock_exclusive(file: &File) -> std::io::Result<bool> {
        match lock_file(file, LOCKFILE_FAIL_IMMEDIATELY) {
            Ok(()) => Ok(true),
            Err(err) => {
                if err.raw_os_error() == Some(ERROR_LOCK_VIOLATION) {
                    Ok(false)
                } else {
                    Err(err)
                }
            }
        }
    }

    #[cfg(windows)]
    fn unlock(file: &File) -> std::io::Result<()> {
        let handle = std::os::windows::io::AsRawHandle::as_raw_handle(file) as HANDLE;
        let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
        let result = unsafe { UnlockFileEx(handle, 0, 1, 0, &mut overlapped) };
        if result != 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    #[cfg(windows)]
    fn lock_file(file: &File, flags: u32) -> std::io::Result<()> {
        let handle = std::os::windows::io::AsRawHandle::as_raw_handle(file) as HANDLE;
        let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
        let result = unsafe {
            LockFileEx(
                handle,
                LOCKFILE_EXCLUSIVE_LOCK | flags,
                0,
                1,
                0,
                &mut overlapped,
            )
        };
        if result != 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    #[cfg(windows)]
    type HANDLE = *mut std::ffi::c_void;

    #[cfg(windows)]
    #[repr(C)]
    struct OVERLAPPED {
        internal: usize,
        internal_high: usize,
        offset: u32,
        offset_high: u32,
        h_event: HANDLE,
    }

    #[cfg(windows)]
    const LOCKFILE_EXCLUSIVE_LOCK: u32 = 0x2;
    #[cfg(windows)]
    const LOCKFILE_FAIL_IMMEDIATELY: u32 = 0x1;
    #[cfg(windows)]
    const ERROR_LOCK_VIOLATION: i32 = 33;

    #[cfg(windows)]
    extern "system" {
        fn LockFileEx(
            h_file: HANDLE,
            flags: u32,
            reserved: u32,
            bytes_to_lock_low: u32,
            bytes_to_lock_high: u32,
            overlapped: *mut OVERLAPPED,
        ) -> i32;
        fn UnlockFileEx(
            h_file: HANDLE,
            reserved: u32,
            bytes_to_unlock_low: u32,
            bytes_to_unlock_high: u32,
            overlapped: *mut OVERLAPPED,
        ) -> i32;
    }

    #[cfg(test)]
    mod tests {
        use super::Lock;

        #[test]
        fn test_lock_is_exclusive() {
            let dir = tempfile::tempdir().expect("create temp dir");
            let path = dir.path().join("lock.lock");
            let lock_a = Lock::open(&path).expect("open lock");
            let guard = lock_a.lock().expect("acquire lock");

            let lock_b = Lock::open(&path).expect("open lock");
            let blocked = lock_b.try_lock().expect("try lock");
            assert!(blocked.is_none());

            drop(guard);
            let guard = lock_b.try_lock().expect("try lock");
            assert!(guard.is_some());
        }

        #[test]
        fn test_lock_serializes_across_threads() {
            use std::sync::mpsc;
            use std::thread;

            let dir = tempfile::tempdir().expect("create temp dir");
            let path = dir.path().join("lock.lock");
            let lock = Lock::open(&path).expect("open lock");

            let (locked_tx, locked_rx) = mpsc::channel();
            let (release_tx, release_rx) = mpsc::channel();
            let (released_tx, released_rx) = mpsc::channel();

            let thread_a = thread::spawn(move || {
                let guard = lock.lock().expect("lock in thread");
                locked_tx.send(()).expect("signal locked");
                release_rx.recv().expect("wait release");
                drop(guard);
                released_tx.send(()).expect("signal released");
            });

            locked_rx.recv().expect("wait locked");
            let lock_b = Lock::open(&path).expect("open lock");
            let blocked = lock_b.try_lock().expect("try lock");
            assert!(blocked.is_none());

            release_tx.send(()).expect("release");
            released_rx.recv().expect("wait released");

            let guard = lock_b.try_lock().expect("try lock");
            assert!(guard.is_some());

            thread_a.join().expect("thread join");
        }
    }
}

pub use imp::{Lock, LockGuard};
