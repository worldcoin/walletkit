//! Artifact sources & traits for loading/caching & managing ZK Artifacts

use std::sync::Arc;

use world_id_core::artifacts::ZkArtifactSource;

/// Opaque binding handle for a Rust ZK artifact source.
///
/// BoltFFI callbacks cannot inherit Rust supertraits, so artifact implementations
/// cross the binding boundary through this class instead of a callback interface.
#[derive(Clone)]
pub struct WalletKitZkArtifacts(Arc<dyn ZkArtifactSource>);

#[boltffi::export]
impl WalletKitZkArtifacts {}

impl WalletKitZkArtifacts {
    #[cfg(feature = "embed-zkeys")]
    pub(super) fn new(source: Arc<dyn ZkArtifactSource>) -> Self {
        Self(source)
    }
}

impl ZkArtifactSource for WalletKitZkArtifacts {
    fn query_material(
        &self,
    ) -> Result<
        Arc<world_id_proof::CircomGroth16Material>,
        world_id_core::artifacts::ZkArtifactError,
    > {
        self.0.query_material()
    }

    fn nullifier_material(
        &self,
    ) -> Result<
        Arc<world_id_proof::CircomGroth16Material>,
        world_id_core::artifacts::ZkArtifactError,
    > {
        self.0.nullifier_material()
    }

    fn ownership_prover(
        &self,
    ) -> Result<
        world_id_proof::OwnershipProver,
        world_id_core::artifacts::ZkArtifactError,
    > {
        self.0.ownership_prover()
    }

    fn ownership_verifier(
        &self,
    ) -> Result<
        world_id_proof::OwnershipVerifier,
        world_id_core::artifacts::ZkArtifactError,
    > {
        self.0.ownership_verifier()
    }
}

#[cfg(all(not(target_arch = "wasm32"), feature = "embed-zkeys"))]
pub mod caching;

/// Sources backed by ZK artifacts embedded in the binary.
#[cfg(feature = "embed-zkeys")]
pub mod embedded;
