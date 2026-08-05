//! This module defines a wrapper for an embedded artifact source

use std::sync::Arc;

use world_id_core::artifacts::{
    cached::CachedZkArtifactSource, error::ZkArtifactError, ZkArtifactSource,
};
use world_id_proof::{
    artifacts::embedded::EmbeddedZkArtifacts as CoreEmbeddedZkArtifacts,
    CircomGroth16Material,
};

/// A wrapper around `world_id_proof::artifacts::EmbeddedZkArtifacts`
///
/// that can be constructed by crate consumers
#[derive(uniffi::Object)]
pub struct EmbeddedZkArtifacts(CachedZkArtifactSource);

impl Default for EmbeddedZkArtifacts {
    fn default() -> Self {
        Self::new()
    }
}

#[uniffi::export]
impl EmbeddedZkArtifacts {
    /// Constructs a new [`EmbeddedZkArtifacts`]
    #[uniffi::constructor]
    #[must_use]
    pub fn new() -> Self {
        Self(CachedZkArtifactSource::new(CoreEmbeddedZkArtifacts))
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
