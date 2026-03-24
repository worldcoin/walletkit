//! Storage path helpers.

use std::path::{Path, PathBuf};

const VAULT_FILENAME: &str = "account.vault.sqlite";
const CACHE_FILENAME: &str = "account.cache.sqlite";
const LOCK_FILENAME: &str = "lock";
const GROTH16_DIRNAME: &str = "groth16";
const QUERY_ZKEY_FILENAME: &str = "OPRFQuery.arks.zkey";
const NULLIFIER_ZKEY_FILENAME: &str = "OPRFNullifier.arks.zkey";
const QUERY_GRAPH_FILENAME: &str = "OPRFQueryGraph.bin";
const NULLIFIER_GRAPH_FILENAME: &str = "OPRFNullifierGraph.bin";

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

    /// Returns the path to the Groth16 material directory.
    #[must_use]
    pub fn groth16_dir(&self) -> PathBuf {
        self.worldid_dir.join(GROTH16_DIRNAME)
    }

    /// Returns the path to the query zkey file.
    #[must_use]
    pub fn query_zkey_path(&self) -> PathBuf {
        self.groth16_dir().join(QUERY_ZKEY_FILENAME)
    }

    /// Returns the path to the nullifier zkey file.
    #[must_use]
    pub fn nullifier_zkey_path(&self) -> PathBuf {
        self.groth16_dir().join(NULLIFIER_ZKEY_FILENAME)
    }

    /// Returns the path to the query graph file.
    #[must_use]
    pub fn query_graph_path(&self) -> PathBuf {
        self.groth16_dir().join(QUERY_GRAPH_FILENAME)
    }

    /// Returns the path to the nullifier graph file.
    #[must_use]
    pub fn nullifier_graph_path(&self) -> PathBuf {
        self.groth16_dir().join(NULLIFIER_GRAPH_FILENAME)
    }
}

#[uniffi::export]
impl StoragePaths {
    /// Builds storage paths rooted at `root`.
    #[uniffi::constructor]
    #[must_use]
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

    /// Returns the path to the Groth16 material directory as a string.
    #[must_use]
    pub fn groth16_dir_path_string(&self) -> String {
        self.groth16_dir().to_string_lossy().to_string()
    }

    /// Returns the path to the query zkey file as a string.
    #[must_use]
    pub fn query_zkey_path_string(&self) -> String {
        self.query_zkey_path().to_string_lossy().to_string()
    }

    /// Returns the path to the nullifier zkey file as a string.
    #[must_use]
    pub fn nullifier_zkey_path_string(&self) -> String {
        self.nullifier_zkey_path().to_string_lossy().to_string()
    }

    /// Returns the path to the query graph file as a string.
    #[must_use]
    pub fn query_graph_path_string(&self) -> String {
        self.query_graph_path().to_string_lossy().to_string()
    }

    /// Returns the path to the nullifier graph file as a string.
    #[must_use]
    pub fn nullifier_graph_path_string(&self) -> String {
        self.nullifier_graph_path().to_string_lossy().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::StoragePaths;
    use std::path::PathBuf;

    #[test]
    fn test_groth16_paths() {
        let root = PathBuf::from("/tmp/walletkit-paths");
        let paths = StoragePaths::new(&root);
        let worldid = root.join("worldid");
        let groth16 = worldid.join("groth16");

        assert_eq!(paths.groth16_dir(), groth16);
        assert_eq!(paths.query_zkey_path(), groth16.join("OPRFQuery.arks.zkey"));
        assert_eq!(
            paths.nullifier_zkey_path(),
            groth16.join("OPRFNullifier.arks.zkey")
        );
        assert_eq!(paths.query_graph_path(), groth16.join("OPRFQueryGraph.bin"));
        assert_eq!(
            paths.nullifier_graph_path(),
            groth16.join("OPRFNullifierGraph.bin")
        );
    }

    #[test]
    fn test_groth16_path_strings() {
        let root = PathBuf::from("/tmp/walletkit-paths");
        let paths = StoragePaths::new(&root);

        assert_eq!(
            paths.groth16_dir_path_string(),
            paths.groth16_dir().to_string_lossy()
        );
        assert_eq!(
            paths.query_zkey_path_string(),
            paths.query_zkey_path().to_string_lossy()
        );
        assert_eq!(
            paths.nullifier_zkey_path_string(),
            paths.nullifier_zkey_path().to_string_lossy()
        );
        assert_eq!(
            paths.query_graph_path_string(),
            paths.query_graph_path().to_string_lossy()
        );
        assert_eq!(
            paths.nullifier_graph_path_string(),
            paths.nullifier_graph_path().to_string_lossy()
        );
    }
}
