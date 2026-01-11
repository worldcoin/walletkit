//! iOS file-based vault store implementation.
//!
//! This module implements `VaultFileStore` using standard file I/O with
//! random access capabilities (seek, read_at, write_at).
//!
//! # Durability
//!
//! The `sync()` method calls `fsync()` to ensure all written data is
//! durably persisted to storage. This is critical for the crash-safe
//! transaction semantics of the vault file.
//!
//! # Concurrency
//!
//! This implementation does NOT provide internal locking. Callers must use
//! `AccountLockManager` to serialize access to the vault file across
//! threads and processes.

use crate::credential_storage::{StorageError, StorageResult};
use crate::credential_storage::platform::VaultFileStore;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Helper to create an IO error from an std::io::Error.
fn io_error<S: Into<String>>(context: S, err: std::io::Error) -> StorageError {
    StorageError::IoError {
        context: context.into(),
        source: err,
    }
}

// IosVaultStore

/// iOS file-based implementation of `VaultFileStore`.
///
/// This implementation provides random-access read/write operations on the
/// vault file with proper durability guarantees.
///
/// # Thread Safety
///
/// The internal file handle is protected by a mutex to allow safe access
/// from multiple threads. However, this does NOT prevent concurrent access
/// from other processes - use `AccountLockManager` for that.
///
/// # Example
///
/// ```ignore
/// let store = IosVaultStore::new("/path/to/account.vault")?;
///
/// // Write some data at offset 0
/// store.write_at(0, b"header data")?;
///
/// // Append more data
/// let offset = store.append(b"record data")?;
///
/// // Ensure durability
/// store.sync()?;
///
/// // Read it back
/// let mut buf = vec![0u8; 11];
/// store.read_at(0, &mut buf)?;
/// assert_eq!(buf, b"header data");
/// ```
#[derive(Debug)]
pub struct IosVaultStore {
    /// Path to the vault file.
    path: PathBuf,
    /// File handle, protected by mutex for thread safety.
    file: Mutex<Option<File>>,
}

impl IosVaultStore {
    /// Creates a new vault store for the given file path.
    ///
    /// The file is NOT opened or created immediately. Use `open()` or
    /// `create()` methods on the `VaultFile` to initialize the vault.
    ///
    /// # Arguments
    ///
    /// * `path` - Path where the vault file will be stored
    pub fn new<P: AsRef<Path>>(path: P) -> StorageResult<Self> {
        let path = path.as_ref().to_path_buf();
        Ok(Self {
            path,
            file: Mutex::new(None),
        })
    }

    /// Opens the vault file if it exists.
    fn open_file(&self) -> StorageResult<()> {
        let mut guard = self.file.lock().map_err(|_| {
            StorageError::lock("Vault store mutex poisoned")
        })?;

        if guard.is_none() {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&self.path)
                .map_err(|e| {
                    io_error(format!("Failed to open vault file '{}'", self.path.display()), e)
                })?;
            *guard = Some(file);
        }

        Ok(())
    }

    /// Creates a new vault file, failing if it already exists.
    fn create_file(&self) -> StorageResult<()> {
        let mut guard = self.file.lock().map_err(|_| {
            StorageError::lock("Vault store mutex poisoned")
        })?;

        // Create parent directory if needed
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                io_error(format!("Failed to create vault directory '{}'", parent.display()), e)
            })?;
        }

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&self.path)
            .map_err(|e| {
                io_error(format!("Failed to create vault file '{}'", self.path.display()), e)
            })?;

        *guard = Some(file);
        Ok(())
    }

    /// Gets a mutable reference to the file, opening it if necessary.
    fn with_file<F, T>(&self, f: F) -> StorageResult<T>
    where
        F: FnOnce(&mut File) -> StorageResult<T>,
    {
        let mut guard = self.file.lock().map_err(|_| {
            StorageError::lock("Vault store mutex poisoned")
        })?;

        let file = guard.as_mut().ok_or_else(|| {
            StorageError::Internal {
                message: "Vault file not open".to_string(),
            }
        })?;

        f(file)
    }
}

impl VaultFileStore for IosVaultStore {
    /// Returns the current length of the vault file in bytes.
    fn len(&self) -> StorageResult<u64> {
        // If file is not open, try to get length from metadata
        let guard = self.file.lock().map_err(|_| {
            StorageError::lock("Vault store mutex poisoned")
        })?;

        if let Some(ref file) = *guard {
            let metadata = file.metadata().map_err(|e| {
                io_error("Failed to get vault file metadata", e)
            })?;
            Ok(metadata.len())
        } else if self.path.exists() {
            // File exists but not open - get size from path
            let metadata = std::fs::metadata(&self.path).map_err(|e| {
                io_error("Failed to get vault file metadata", e)
            })?;
            Ok(metadata.len())
        } else {
            Ok(0)
        }
    }

    /// Reads bytes from the vault file at the specified offset.
    ///
    /// # Arguments
    ///
    /// * `offset` - Byte offset to read from
    /// * `len` - Number of bytes to read
    ///
    /// # Returns
    ///
    /// A vector containing the requested bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The file is not open
    /// - The offset is beyond the end of the file
    /// - The read cannot complete (I/O error)
    fn read_at(&self, offset: u64, len: u32) -> StorageResult<Vec<u8>> {
        if len == 0 {
            return Ok(Vec::new());
        }

        self.with_file(|file| {
            file.seek(SeekFrom::Start(offset)).map_err(|e| {
                io_error(format!("Failed to seek to offset {offset}"), e)
            })?;

            let mut buf = vec![0u8; len as usize];
            file.read_exact(&mut buf).map_err(|e| {
                io_error(format!("Failed to read {len} bytes at offset {offset}"), e)
            })?;

            Ok(buf)
        })
    }

    /// Writes bytes to the vault file at the specified offset.
    ///
    /// This may extend the file if writing beyond the current end.
    /// Data is NOT automatically synced to disk - call `sync()` after
    /// completing a transaction.
    ///
    /// # Arguments
    ///
    /// * `offset` - Byte offset to write at
    /// * `bytes` - Data to write
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The file is not open
    /// - The write fails (I/O error)
    fn write_at(&self, offset: u64, bytes: &[u8]) -> StorageResult<()> {
        if bytes.is_empty() {
            return Ok(());
        }

        self.with_file(|file| {
            file.seek(SeekFrom::Start(offset)).map_err(|e| {
                io_error(format!("Failed to seek to offset {offset}"), e)
            })?;

            file.write_all(bytes).map_err(|e| {
                io_error(format!("Failed to write {} bytes at offset {offset}", bytes.len()), e)
            })?;

            Ok(())
        })
    }

    /// Appends data to the end of the vault file.
    ///
    /// # Arguments
    ///
    /// * `bytes` - Data to append
    ///
    /// # Returns
    ///
    /// The offset where the data was written.
    ///
    /// # Errors
    ///
    /// Returns an error if the append fails.
    fn append(&self, bytes: &[u8]) -> StorageResult<u64> {
        if bytes.is_empty() {
            return self.len();
        }

        self.with_file(|file| {
            let offset = file.seek(SeekFrom::End(0)).map_err(|e| {
                io_error("Failed to seek to end", e)
            })?;

            file.write_all(bytes).map_err(|e| {
                io_error(format!("Failed to append {} bytes", bytes.len()), e)
            })?;

            Ok(offset)
        })
    }

    /// Syncs all written data to persistent storage.
    ///
    /// This calls `fsync()` to ensure durability. Always call this after
    /// completing a vault transaction before releasing the account lock.
    ///
    /// # Errors
    ///
    /// Returns an error if the sync fails.
    fn sync(&self) -> StorageResult<()> {
        self.with_file(|file| {
            file.sync_all().map_err(|e| io_error("Failed to sync vault file", e))
        })
    }

    /// Sets the length of the vault file.
    ///
    /// If `len` is less than the current length, the file is truncated.
    /// If `len` is greater than the current length, the file is extended
    /// with zero bytes.
    ///
    /// # Arguments
    ///
    /// * `len` - The new length of the file in bytes
    ///
    /// # Errors
    ///
    /// Returns an error if the operation fails.
    fn set_len(&self, len: u64) -> StorageResult<()> {
        self.with_file(|file| {
            file.set_len(len).map_err(|e| io_error(format!("Failed to set vault file length to {len}"), e))
        })
    }
}

impl IosVaultStore {
    /// Opens an existing vault file.
    ///
    /// # Errors
    ///
    /// Returns an error if the file doesn't exist or cannot be opened.
    pub fn open_existing(&self) -> StorageResult<()> {
        self.open_file()
    }

    /// Creates a new vault file.
    ///
    /// # Errors
    ///
    /// Returns an error if the file already exists or cannot be created.
    pub fn create_new(&self) -> StorageResult<()> {
        self.create_file()
    }

    /// Opens an existing file or creates a new one.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be opened or created.
    pub fn open_or_create(&self) -> StorageResult<()> {
        let mut guard = self.file.lock().map_err(|_| {
            StorageError::lock("Vault store mutex poisoned")
        })?;

        if guard.is_none() {
            // Create parent directory if needed
            if let Some(parent) = self.path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    io_error(format!("Failed to create vault directory '{}'", parent.display()), e)
                })?;
            }

            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(&self.path)
                .map_err(|e| {
                    io_error(format!("Failed to open/create vault file '{}'", self.path.display()), e)
                })?;

            *guard = Some(file);
        }

        Ok(())
    }

    /// Returns true if the vault file exists on disk.
    #[must_use]
    pub fn exists(&self) -> bool {
        self.path.exists()
    }
}
