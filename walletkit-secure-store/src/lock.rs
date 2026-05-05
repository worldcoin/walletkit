//! Cross-process exclusive lock for serializing storage writes.
//!
//! On native platforms (Unix, Windows) a file-based `flock` / `LockFileEx`
//! lock is used to serialize writes across processes.
//!
//! On `wasm32` targets the lock is a no-op because the runtime is
//! single-threaded (sqlite-wasm-rs is compiled with `SQLITE_THREADSAFE=0`)
//! and runs in a dedicated Web Worker.

use std::path::Path;

use crate::error::StoreResult;

#[cfg(target_arch = "wasm32")]
mod imp {
    use super::{Path, StoreResult};

    /// No-op lock for WASM.
    #[derive(Debug, Clone)]
    pub struct Lock;

    /// No-op guard.
    #[derive(Debug)]
    pub struct LockGuard;

    impl Lock {
        /// Opens a no-op lock.
        pub fn open(_path: &Path) -> StoreResult<Self> {
            Ok(Self)
        }

        /// Acquires a no-op lock.
        pub fn lock(&self) -> StoreResult<LockGuard> {
            Ok(LockGuard)
        }

        /// Attempts to acquire a no-op lock.
        pub fn try_lock(&self) -> StoreResult<Option<LockGuard>> {
            Ok(Some(LockGuard))
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
mod imp {
    use super::{Path, StoreResult};
    use crate::error::StoreError;
    use std::fs::{self, File, OpenOptions};
    use std::sync::Arc;

    /// File-backed exclusive lock that serializes mutations across processes.
    #[derive(Debug, Clone)]
    pub struct Lock {
        file: Arc<File>,
    }

    /// Guard holding the exclusive lock for its lifetime.
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

        /// Acquires the exclusive lock, blocking until available.
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
        /// Returns `Ok(None)` if the lock is held by another process.
        ///
        /// # Errors
        ///
        /// Returns an error if the lock attempt fails for reasons other than
        /// the lock being held.
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
}

pub use imp::{Lock, LockGuard};

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::Lock;
    use uuid::Uuid;

    fn temp_lock_path() -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("walletkit-secure-store-lock-{}.lock", Uuid::new_v4()));
        path
    }

    #[test]
    fn lock_is_exclusive() {
        let path = temp_lock_path();
        let lock_a = Lock::open(&path).expect("open lock");
        let guard = lock_a.lock().expect("acquire lock");

        let lock_b = Lock::open(&path).expect("open lock");
        let blocked = lock_b.try_lock().expect("try lock");
        assert!(blocked.is_none());

        drop(guard);
        let guard = lock_b.try_lock().expect("try lock");
        assert!(guard.is_some());

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn lock_serializes_across_threads() {
        let path = temp_lock_path();
        let lock = Lock::open(&path).expect("open lock");

        let (locked_tx, locked_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let (released_tx, released_rx) = std::sync::mpsc::channel();

        let path_clone = path.clone();
        let thread_a = std::thread::spawn(move || {
            let guard = lock.lock().expect("lock in thread");
            locked_tx.send(()).expect("signal locked");
            release_rx.recv().expect("wait release");
            drop(guard);
            released_tx.send(()).expect("signal released");
            let _ = std::fs::remove_file(path_clone);
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
