//! This module defines a wrapper for an embedded artifact source

use std::sync::Arc;

use world_id_core::artifacts::{
    cached::CachedZkArtifactSource, error::ZkArtifactError, ZkArtifactSource,
};
use world_id_proof::{
    artifacts::embedded::EmbeddedZkArtifacts as CoreEmbeddedZkArtifacts,
    CircomGroth16Material,
};

use super::WalletKitZkArtifacts;

/// A wrapper around `world_id_proof::artifacts::EmbeddedZkArtifacts`
///
/// that can be constructed by crate consumers
#[derive(Clone)]
pub struct EmbeddedZkArtifacts(CachedZkArtifactSource);

impl Default for EmbeddedZkArtifacts {
    fn default() -> Self {
        Self::new()
    }
}

#[boltffi::export]
impl EmbeddedZkArtifacts {
    /// Constructs a new [`EmbeddedZkArtifacts`]
    #[must_use]
    pub fn new() -> Self {
        Self(CachedZkArtifactSource::new(CoreEmbeddedZkArtifacts))
    }

    /// Returns this caching implementation as a `WalletKit` ZK artifact source.
    ///
    /// This explicit conversion is required by foreign-language bindings, which do not preserve
    /// Rust blanket trait implementations as class inheritance.
    #[must_use]
    pub fn as_zk_artifact_source(&self) -> WalletKitZkArtifacts {
        WalletKitZkArtifacts::new(Arc::new(self.clone()))
    }
}

impl ZkArtifactSource for EmbeddedZkArtifacts {
    fn query_material(&self) -> Result<Arc<CircomGroth16Material>, ZkArtifactError> {
        self.0.query_material()
    }

    fn nullifier_material(
        &self,
    ) -> Result<Arc<CircomGroth16Material>, ZkArtifactError> {
        self.0.nullifier_material()
    }

    fn ownership_prover(
        &self,
    ) -> Result<world_id_proof::OwnershipProver, ZkArtifactError> {
        self.0.ownership_prover()
    }

    fn ownership_verifier(
        &self,
    ) -> Result<world_id_proof::OwnershipVerifier, ZkArtifactError> {
        self.0.ownership_verifier()
    }
}
