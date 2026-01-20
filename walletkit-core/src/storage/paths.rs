//! Storage path helpers.

use std::path::{Path, PathBuf};

const VAULT_FILENAME: &str = "account.vault.sqlite";
const CACHE_FILENAME: &str = "account.cache.sqlite";
const LOCK_FILENAME: &str = "lock";

/// Paths for credential storage artifacts under `<root>/worldid`.
#[derive(Debug, Clone, uniffi::Object)]
pub struct StoragePaths {
    root: PathBuf,
    worldid_dir: PathBuf,
}

impl StoragePaths {
    /// Builds storage paths rooted at `root`.
    #[must_use]
    pub fn new(root: impl AsRef<Path>) -> Self {
        let root = root.as_ref().to_path_buf();
        let worldid_dir = root.join("worldid");
        Self { root, worldid_dir }
    }

    /// Returns the storage root directory.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Returns the World ID storage directory.
    #[must_use]
    pub fn worldid_dir(&self) -> &Path {
        &self.worldid_dir
    }

    /// Returns the path to the vault database.
    #[must_use]
    pub fn vault_db_path(&self) -> PathBuf {
        self.worldid_dir.join(VAULT_FILENAME)
    }

    /// Returns the path to the cache database.
    #[must_use]
    pub fn cache_db_path(&self) -> PathBuf {
        self.worldid_dir.join(CACHE_FILENAME)
    }

    /// Returns the path to the lock file.
    #[must_use]
    pub fn lock_path(&self) -> PathBuf {
        self.worldid_dir.join(LOCK_FILENAME)
    }
}

#[uniffi::export]
impl StoragePaths {
    /// Builds storage paths rooted at `root`.
    #[uniffi::constructor]
    pub fn from_root(root: String) -> Self {
        Self::new(PathBuf::from(root))
    }

    /// Returns the storage root directory as a string.
    #[must_use]
    pub fn root_path_string(&self) -> String {
        self.root.to_string_lossy().to_string()
    }

    /// Returns the World ID storage directory as a string.
    #[must_use]
    pub fn worldid_dir_path_string(&self) -> String {
        self.worldid_dir.to_string_lossy().to_string()
    }

    /// Returns the path to the vault database as a string.
    #[must_use]
    pub fn vault_db_path_string(&self) -> String {
        self.vault_db_path().to_string_lossy().to_string()
    }

    /// Returns the path to the cache database as a string.
    #[must_use]
    pub fn cache_db_path_string(&self) -> String {
        self.cache_db_path().to_string_lossy().to_string()
    }

    /// Returns the path to the lock file as a string.
    #[must_use]
    pub fn lock_path_string(&self) -> String {
        self.lock_path().to_string_lossy().to_string()
    }
}
