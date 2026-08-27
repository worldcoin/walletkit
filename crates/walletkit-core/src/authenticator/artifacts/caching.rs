//! This module defines the `CachingZkArtifacts` struct - an artifact source that caches the query
//! & nullifier material on the filesystem.

use std::{path::Path, sync::Arc};

use world_id_core::artifacts::{
    error::ZkArtifactError, ZkArtifactKind, ZkArtifactSourceExt,
};
use world_id_proof::{
    artifacts::{
        cached::CachedZkArtifactSource, embedded::EmbeddedZkArtifacts, ZkArtifactSource,
    },
    CircomGroth16Material, CircomGroth16MaterialBuilder, OwnershipProver,
    OwnershipVerifier, ZkeyError,
};

use crate::{error::WalletKitError, storage::StoragePaths};

use super::WalletKitZkArtifacts;

/// A crate specific source for ZK Artifacts
///
/// Loads ZK Artifacts from embedded data & caches the resulting artifacts (for the Query &
/// Nullifier proofs) on the filesystem.
///
/// Primary reason for caching is amortization of decompression costs.
#[derive(Clone)]
pub struct CachingZkArtifacts(Arc<CachedZkArtifactSource>);

#[boltffi::export]
impl CachingZkArtifacts {
    /// Constructs a new [`CachingZkArtifacts`]
    #[must_use]
    pub fn new(storage_paths: &StoragePaths) -> Self {
        let inner =
            CachingZkArtifactsInner::new(Arc::new(storage_paths.clone())).cached();
        Self(Arc::new(inner))
    }

    /// Returns this caching implementation as a `WalletKit` ZK artifact source.
    ///
    /// This explicit conversion is required by foreign-language bindings, which do not preserve
    /// Rust blanket trait implementations as class inheritance.
    #[must_use]
    pub fn as_zk_artifact_source(&self) -> WalletKitZkArtifacts {
        WalletKitZkArtifacts::new(Arc::new(self.clone()))
    }

    /// Preloads the nullifier & query materials and caches them to the filesystem.
    ///
    /// In practice - this methods loads the materials using the normal path and discards the
    /// results.
    ///
    /// # Errors
    /// This method can return an error if a filesystem operation fails when loading the cached
    /// artifacts.
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

impl ZkArtifactSource for CachingZkArtifacts {
    fn query_material(&self) -> Result<Arc<CircomGroth16Material>, ZkArtifactError> {
        self.0.query_material()
    }

    fn nullifier_material(
        &self,
    ) -> Result<Arc<CircomGroth16Material>, ZkArtifactError> {
        self.0.nullifier_material()
    }

    fn ownership_prover(&self) -> Result<OwnershipProver, ZkArtifactError> {
        self.0.ownership_prover()
    }

    fn ownership_verifier(&self) -> Result<OwnershipVerifier, ZkArtifactError> {
        self.0.ownership_verifier()
    }
}

/// An inner implementation layer of the caching zk artifacts source.
///
/// It implements the caching logic & exists to be wrapped by the `CachedZkArtifactSource` which
/// provides in-memory caching of the artifacts.
#[derive(Clone)]
struct CachingZkArtifactsInner {
    storage_paths: Arc<StoragePaths>,
    inner: Arc<dyn ZkArtifactSource>,
}

impl CachingZkArtifactsInner {
    #[must_use]
    fn new(storage_paths: Arc<StoragePaths>) -> Self {
        Self {
            storage_paths,
            inner: Arc::new(EmbeddedZkArtifacts),
        }
    }
}

impl ZkArtifactSource for CachingZkArtifactsInner {
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

impl CachingZkArtifactsInner {
    /// Attempts to load the **query** Gorth16 material from cache
    ///
    /// Returns `Ok(None)` if cached material does not exist or is invalid/corrupted
    ///
    /// # Errors
    /// Can fail on an io operation when loading files from cache
    fn try_query_material_from_cache(
        &self,
    ) -> Result<Option<Arc<CircomGroth16Material>>, ZkArtifactError> {
        Self::try_material_from_cache(
            ZkArtifactKind::QueryMaterial,
            self.storage_paths.query_zkey_path(),
            self.storage_paths.query_graph_path(),
        )
    }

    /// Attempts to load the **nullifier** Gorth16 material from cache
    ///
    /// Returns `Ok(None)` if cached material does not exist or is invalid/corrupted
    ///
    /// # Errors
    /// Can fail on an io operation when loading files from cache
    fn try_nullifier_material_from_cache(
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

        ensure_parent_dir_of(kind, zkey_path)?;
        ensure_parent_dir_of(kind, graph_path)?;

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

        let (zkey_fingerprint, graph_fingerprint) = match kind {
            ZkArtifactKind::QueryMaterial => (
                world_id_proof::QUERY_ZKEY_FINGERPRINT,
                world_id_proof::QUERY_GRAPH_FINGERPRINT,
            ),
            ZkArtifactKind::NullifierMaterial => (
                world_id_proof::NULLIFIER_ZKEY_FINGERPRINT,
                world_id_proof::NULLIFIER_GRAPH_FINGERPRINT,
            ),
            // NOTE: Odd edge case because ZkArtifactKind also covers ownership proof artifacts
            //       but this should never happen in practice
            _ => ("", ""),
        };

        match CircomGroth16MaterialBuilder::new()
            .fingerprint_graph(graph_fingerprint.to_string())
            .fingerprint_zkey(zkey_fingerprint.to_string())
            // TODO: We should expose https://github.com/worldcoin/world-id-protocol/blob/main/crates/proof/src/nullifier_proof.rs#L69-L78
            //       and reuse it here
            .bbf_num_2_bits_helper()
            .bbf_inv()
            .bbf_legendre()
            .bbf_sqrt_input()
            .bbf_sqrt_unchecked()
            .build_from_paths(zkey_path, graph_path)
        {
            Ok(material) => Ok(Some(Arc::new(material))),
            // Cache is invalid or corrupted - return None so material is reloaded and re-cached
            Err(
                ZkeyError::GraphFingerprintMismatch(_)
                | ZkeyError::ZkeyFingerprintMismatch(_)
                | ZkeyError::ZkeyInvalid(_)
                | ZkeyError::GraphInvalid(_),
            ) => Ok(None),
            Err(other) => Err(ZkArtifactError::Load {
                kind,
                message: other.to_string(),
            }),
        }
    }
}

fn ensure_parent_dir_of(
    kind: ZkArtifactKind,
    zkey_path: impl AsRef<Path>,
) -> Result<(), ZkArtifactError> {
    let zkey_path = zkey_path.as_ref();

    if let Some(parent) = zkey_path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| ZkArtifactError::Load {
            kind,
            message: format!(
                "Failed to create parent directory for {}: {error}",
                zkey_path.display()
            ),
        })?;
    }

    Ok(())
}
