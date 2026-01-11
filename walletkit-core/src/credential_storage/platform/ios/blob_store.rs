//! iOS file system-based atomic blob store implementation.
//!
//! This module implements `AtomicBlobStore` using standard file system
//! operations with atomic write semantics (write-to-temp-then-rename).
//!
//! # Atomic Write Pattern
//!
//! To ensure crash safety, writes follow this sequence:
//!
//! 1. Write data to a temporary file in the same directory
//! 2. Call `fsync()` on the temporary file
//! 3. Atomically rename the temporary file to the target name
//! 4. Call `fsync()` on the parent directory
//!
//! This guarantees that readers always see either the old content or the
//! new content, never a partial write.

use crate::credential_storage::{StorageError, StorageResult};
use crate::credential_storage::platform::AtomicBlobStore;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::io::AsRawFd;

/// Helper to create an IO error from an std::io::Error.
fn io_error<S: Into<String>>(context: S, err: std::io::Error) -> StorageError {
    StorageError::IoError {
        context: context.into(),
        source: err,
    }
}

// IosBlobStore

/// iOS file system-based implementation of `AtomicBlobStore`.
///
/// This implementation provides atomic read/write/delete operations for
/// small files (account state, pending actions, etc.).
///
/// # Thread Safety
///
/// File operations are atomic at the OS level. Multiple threads or processes
/// can safely access the same blob store, though external locking is still
/// recommended for multi-file transactions.
///
/// # Example
///
/// ```ignore
/// let store = IosBlobStore::new("/path/to/account/dir")?;
///
/// // Write atomically
/// store.write_atomic("state.bin", b"some data")?;
///
/// // Read back
/// let data = store.read("state.bin")?;
/// assert_eq!(data, Some(b"some data".to_vec()));
///
/// // Delete
/// store.delete("state.bin")?;
/// ```
#[derive(Debug, Clone)]
pub struct IosBlobStore {
    /// Directory path where blobs are stored.
    directory: PathBuf,
}

impl IosBlobStore {
    /// Creates a new blob store for the given directory.
    ///
    /// # Arguments
    ///
    /// * `directory` - The directory where blobs will be stored.
    ///   Will be created if it doesn't exist.
    ///
    /// # Errors
    ///
    /// Returns an error if the directory cannot be created.
    pub fn new<P: AsRef<Path>>(directory: P) -> StorageResult<Self> {
        let directory = directory.as_ref().to_path_buf();

        // Create directory if it doesn't exist
        fs::create_dir_all(&directory).map_err(|e| {
            io_error(
                format!("Failed to create blob store directory '{}'", directory.display()),
                e,
            )
        })?;

        Ok(Self { directory })
    }

    /// Returns the full path for a blob with the given filename.
    fn blob_path(&self, filename: &str) -> PathBuf {
        self.directory.join(filename)
    }

    /// Returns the path for a temporary file used during atomic writes.
    fn temp_path(&self, filename: &str) -> PathBuf {
        self.directory.join(format!(".{filename}.tmp"))
    }

    /// Syncs a file to disk.
    #[cfg(unix)]
    fn sync_file(file: &File) -> StorageResult<()> {
        file.sync_all().map_err(|e| io_error("Failed to sync file", e))
    }

    #[cfg(not(unix))]
    fn sync_file(file: &File) -> StorageResult<()> {
        file.sync_all().map_err(|e| io_error("Failed to sync file", e))
    }

    /// Syncs a directory to disk (ensures rename is durable).
    #[cfg(unix)]
    fn sync_directory(&self) -> StorageResult<()> {
        let dir = File::open(&self.directory).map_err(|e| {
            io_error(
                format!("Failed to open directory for sync '{}'", self.directory.display()),
                e,
            )
        })?;

        // fsync on the directory to ensure the rename is durable
        unsafe {
            if libc::fsync(dir.as_raw_fd()) != 0 {
                let err = std::io::Error::last_os_error();
                return Err(io_error("Failed to fsync directory", err));
            }
        }

        Ok(())
    }

    #[cfg(not(unix))]
    fn sync_directory(&self) -> StorageResult<()> {
        // On non-Unix platforms, we can't easily sync a directory.
        // The rename should still be atomic on most modern file systems.
        Ok(())
    }
}

impl AtomicBlobStore for IosBlobStore {
    /// Reads a blob from the store.
    ///
    /// # Arguments
    ///
    /// * `filename` - The name of the blob to read
    ///
    /// # Returns
    ///
    /// - `Ok(Some(data))` if the blob exists
    /// - `Ok(None)` if the blob doesn't exist
    ///
    /// # Errors
    ///
    /// Returns an error if reading the file fails (other than not found).
    fn read(&self, filename: &str) -> StorageResult<Option<Vec<u8>>> {
        let path = self.blob_path(filename);

        match fs::read(&path) {
            Ok(data) => Ok(Some(data)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(io_error(format!("Failed to read blob '{}'", path.display()), e)),
        }
    }

    /// Atomically writes a blob to the store.
    ///
    /// Uses the write-to-temp-then-rename pattern for crash safety.
    ///
    /// # Arguments
    ///
    /// * `filename` - The name of the blob to write
    /// * `data` - The data to write
    ///
    /// # Errors
    ///
    /// Returns an error if writing fails at any stage.
    fn write_atomic(&self, filename: &str, data: &[u8]) -> StorageResult<()> {
        let final_path = self.blob_path(filename);
        let temp_path = self.temp_path(filename);

        // Write to temporary file
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&temp_path)
            .map_err(|e| {
                io_error(format!("Failed to create temporary file '{}'", temp_path.display()), e)
            })?;

        file.write_all(data).map_err(|e| {
            io_error(format!("Failed to write to temporary file '{}'", temp_path.display()), e)
        })?;

        // Sync the file to disk
        Self::sync_file(&file)?;

        // Close the file before renaming
        drop(file);

        // Atomically rename temp file to final name
        fs::rename(&temp_path, &final_path).map_err(|e| {
            // Try to clean up temp file on failure
            let _ = fs::remove_file(&temp_path);
            io_error(
                format!("Failed to rename '{}' to '{}'", temp_path.display(), final_path.display()),
                e,
            )
        })?;

        // Sync directory to ensure rename is durable
        self.sync_directory()?;

        Ok(())
    }

    /// Deletes a blob from the store.
    ///
    /// # Arguments
    ///
    /// * `filename` - The name of the blob to delete
    ///
    /// # Errors
    ///
    /// Returns an error if deletion fails (other than file not found).
    /// Deleting a non-existent file is not an error.
    fn delete(&self, filename: &str) -> StorageResult<()> {
        let path = self.blob_path(filename);

        match fs::remove_file(&path) {
            Ok(()) => {
                // Sync directory to ensure deletion is durable
                self.sync_directory()?;
                Ok(())
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // File doesn't exist - not an error
                Ok(())
            }
            Err(e) => Err(io_error(format!("Failed to delete blob '{}'", path.display()), e)),
        }
    }

    /// Checks if a blob exists in the store.
    ///
    /// # Arguments
    ///
    /// * `filename` - The name of the blob to check
    ///
    /// # Returns
    ///
    /// `true` if the blob exists, `false` otherwise.
    fn exists(&self, filename: &str) -> StorageResult<bool> {
        let path = self.blob_path(filename);
        Ok(path.exists())
    }
}
