use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

use world_id_core::artifacts::{error::ZkArtifactError, ZkArtifactKind};
use world_id_proof::{
    artifacts::{embedded::EmbeddedZkArtifacts, ZkArtifactSource},
    CircomGroth16Material, CircomGroth16MaterialBuilder, OwnershipProver,
    OwnershipVerifier,
};

use crate::{
    error::WalletKitError,
    storage::{StorageError, StoragePaths, StorageResult},
};

/// A WalletKit specific source for ZK Artifacts
///
/// Performs loading & caching of the provided nullifier & query materials to the filesystem.
///
/// ownership material is delegated to the underlying source.
#[derive(Clone, uniffi::Object)]
pub struct ZkArtifacts {
    storage_paths: Arc<StoragePaths>,
    inner: Arc<dyn ZkArtifactSource>,
}

#[uniffi::export]
impl ZkArtifacts {
    #[uniffi::constructor]
    pub fn new(storage_paths: Arc<StoragePaths>) -> Self {
        Self {
            storage_paths,
            inner: Arc::new(EmbeddedZkArtifacts),
        }
    }

    /// Preloads the nullifier & query materials and caches them to the filesystem.
    ///
    /// In practice - this methods loads the materials using the normal path and discards the
    /// results.
    pub fn preload(&self) -> Result<(), WalletKitError> {
        let _query_material = self.query_material().map_err(|error| {
            WalletKitError::Groth16MaterialEmbeddedLoad {
                error: format!("Failed to preload query material: {error}"),
            }
        })?;
        let _nullifier_material = self.nullifier_material().map_err(|error| {
            WalletKitError::Groth16MaterialEmbeddedLoad {
                error: format!("Failed to preload nullifier material: {error}"),
            }
        })?;

        Ok(())
    }
}

impl ZkArtifactSource for ZkArtifacts {
    fn query_material(&self) -> Result<Arc<CircomGroth16Material>, ZkArtifactError> {
        let maybe_query_material = self.try_query_material_from_cache()?;
        if let Some(query_material) = maybe_query_material {
            return Ok(query_material);
        }

        let query_material = self.inner.query_material()?;

        Self::cache_material(
            &query_material,
            ZkArtifactKind::QueryMaterial,
            self.storage_paths.query_zkey_path(),
            self.storage_paths.query_graph_path(),
        )?;

        Ok(query_material)
    }

    fn nullifier_material(
        &self,
    ) -> Result<Arc<CircomGroth16Material>, ZkArtifactError> {
        let maybe_nullifier_material = self.try_nullifier_material_from_cache()?;
        if let Some(nullifier_material) = maybe_nullifier_material {
            return Ok(nullifier_material);
        }

        let nullifier_material = self.inner.nullifier_material()?;

        Self::cache_material(
            &nullifier_material,
            ZkArtifactKind::NullifierMaterial,
            self.storage_paths.nullifier_zkey_path(),
            self.storage_paths.nullifier_graph_path(),
        )?;

        Ok(nullifier_material)
    }

    fn ownership_prover(&self) -> Result<OwnershipProver, ZkArtifactError> {
        self.inner.ownership_prover()
    }

    fn ownership_verifier(&self) -> Result<OwnershipVerifier, ZkArtifactError> {
        self.inner.ownership_verifier()
    }
}

impl ZkArtifacts {
    pub fn try_query_material_from_cache(
        &self,
    ) -> Result<Option<Arc<CircomGroth16Material>>, ZkArtifactError> {
        Self::try_material_from_cache(
            ZkArtifactKind::QueryMaterial,
            self.storage_paths.query_zkey_path(),
            self.storage_paths.query_graph_path(),
        )
    }

    pub fn try_nullifier_material_from_cache(
        &self,
    ) -> Result<Option<Arc<CircomGroth16Material>>, ZkArtifactError> {
        Self::try_material_from_cache(
            ZkArtifactKind::NullifierMaterial,
            self.storage_paths.nullifier_zkey_path(),
            self.storage_paths.nullifier_graph_path(),
        )
    }

    fn cache_material(
        material: &CircomGroth16Material,
        kind: ZkArtifactKind,
        zkey_path: impl AsRef<Path>,
        graph_path: impl AsRef<Path>,
    ) -> Result<(), ZkArtifactError> {
        let zkey_path = zkey_path.as_ref();
        let graph_path = graph_path.as_ref();

        material
            .serializer()
            .to_paths(zkey_path, graph_path)
            .map_err(|error| {
                // TODO: Should this be a Store/Cache/Save error instead?
                ZkArtifactError::Load {
                    kind,
                    message: error.to_string(),
                }
            })
    }

    fn try_material_from_cache(
        kind: ZkArtifactKind,
        zkey_path: impl AsRef<Path>,
        graph_path: impl AsRef<Path>,
    ) -> Result<Option<Arc<CircomGroth16Material>>, ZkArtifactError> {
        let zkey_path = zkey_path.as_ref();
        let graph_path = graph_path.as_ref();

        if !(zkey_path.exists() && graph_path.exists()) {
            return Ok(None);
        }

        let material = CircomGroth16MaterialBuilder::new()
            .build_from_paths(zkey_path, graph_path)
            .map_err(|error| ZkArtifactError::Load {
                kind,
                message: error.to_string(),
            })?;

        Ok(Some(Arc::new(material)))
    }
}

fn write_atomic(path: &Path, bytes: &[u8]) -> StorageResult<()> {
    let tmp_path = PathBuf::from(format!("{}.tmp", path.to_string_lossy()));
    fs::write(&tmp_path, bytes)
        .map_err(|error| StorageError::CacheDb(error.to_string()))?;
    fs::rename(&tmp_path, path)
        .map_err(|error| StorageError::CacheDb(error.to_string()))
}
