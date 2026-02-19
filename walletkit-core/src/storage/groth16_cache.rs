//! Helpers for caching embedded Groth16 material under [`StoragePaths`].

use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use super::{StorageError, StoragePaths, StorageResult};

fn write_atomic(path: &Path, bytes: &[u8]) -> StorageResult<()> {
    let tmp_path = PathBuf::from(format!("{}.tmp", path.to_string_lossy()));
    fs::write(&tmp_path, bytes)
        .map_err(|error| StorageError::CacheDb(error.to_string()))?;
    fs::rename(&tmp_path, path)
        .map_err(|error| StorageError::CacheDb(error.to_string()))
}

/// Writes embedded Groth16 material to the cache paths managed by [`StoragePaths`].
///
/// This operation is idempotent and atomically rewrites all managed files.
///
/// # Errors
///
/// Returns an error if embedded material cannot be loaded or cache files cannot be written.
#[uniffi::export]
pub fn cache_embedded_groth16_material(paths: Arc<StoragePaths>) -> StorageResult<()> {
    let files = world_id_core::proof::load_embedded_circuit_files()
        .map_err(|error| StorageError::CacheDb(error.to_string()))?;

    fs::create_dir_all(paths.groth16_dir())
        .map_err(|error| StorageError::CacheDb(error.to_string()))?;

    write_atomic(&paths.query_zkey_path(), &files.query_zkey)?;
    write_atomic(&paths.nullifier_zkey_path(), &files.nullifier_zkey)?;
    write_atomic(&paths.query_graph_path(), &files.query_graph)?;
    write_atomic(&paths.nullifier_graph_path(), &files.nullifier_graph)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{fs, sync::Arc};

    use super::cache_embedded_groth16_material;
    use crate::storage::StoragePaths;

    fn temp_root() -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("walletkit-groth16-cache-{}", uuid::Uuid::new_v4()));
        path
    }

    #[test]
    fn test_cache_embedded_groth16_material_writes_all_files() {
        let root = temp_root();
        let paths = Arc::new(StoragePaths::new(&root));

        cache_embedded_groth16_material(paths.clone())
            .expect("cache embedded material");

        assert!(paths.groth16_dir().is_dir());
        assert!(paths.query_zkey_path().is_file());
        assert!(paths.nullifier_zkey_path().is_file());
        assert!(paths.query_graph_path().is_file());
        assert!(paths.nullifier_graph_path().is_file());

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn test_cache_embedded_groth16_material_is_idempotent() {
        let root = temp_root();
        let paths = Arc::new(StoragePaths::new(&root));

        cache_embedded_groth16_material(paths.clone()).expect("first cache");
        let first_query_len = fs::metadata(paths.query_zkey_path())
            .expect("query zkey metadata")
            .len();

        cache_embedded_groth16_material(paths.clone()).expect("second cache");
        let second_query_len = fs::metadata(paths.query_zkey_path())
            .expect("query zkey metadata")
            .len();

        assert_eq!(first_query_len, second_query_len);
        assert!(paths.nullifier_zkey_path().is_file());
        assert!(paths.query_graph_path().is_file());
        assert!(paths.nullifier_graph_path().is_file());

        let _ = fs::remove_dir_all(root);
    }
}
