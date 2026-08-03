use std::sync::Arc;

use world_id_core::artifacts::{error::ZkArtifactError, ZkArtifactSource};
use world_id_proof::{
    artifacts::embedded::EmbeddedZkArtifacts as CoreEmbeddedZkArtifacts,
    CircomGroth16Material,
};

/// A wrapper around `world_id_proof::artifacts::EmbeddedZkArtifacts`
///
/// that can be constructed by crate consumers
#[derive(Debug, Clone, uniffi::Object)]
pub struct EmbeddedZkArtifacts;

#[uniffi::export]
impl EmbeddedZkArtifacts {
    #[uniffi::constructor]
    pub const fn new() -> Self {
        Self
    }
}

impl ZkArtifactSource for EmbeddedZkArtifacts {
    fn query_material(&self) -> Result<Arc<CircomGroth16Material>, ZkArtifactError> {
        CoreEmbeddedZkArtifacts.query_material()
    }

    fn nullifier_material(
        &self,
    ) -> Result<Arc<CircomGroth16Material>, ZkArtifactError> {
        CoreEmbeddedZkArtifacts.nullifier_material()
    }

    fn ownership_prover(
        &self,
    ) -> Result<world_id_proof::OwnershipProver, ZkArtifactError> {
        CoreEmbeddedZkArtifacts.ownership_prover()
    }

    fn ownership_verifier(
        &self,
    ) -> Result<world_id_proof::OwnershipVerifier, ZkArtifactError> {
        CoreEmbeddedZkArtifacts.ownership_verifier()
    }
}
