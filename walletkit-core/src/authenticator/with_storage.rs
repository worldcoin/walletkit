use serde::{Deserialize, Serialize};
use world_id_core::primitives::authenticator::AuthenticatorPublicKeySet;
use world_id_core::primitives::merkle::MerkleInclusionProof;
use world_id_core::primitives::TREE_DEPTH;

use crate::error::WalletKitError;

use super::Authenticator;

/// The amount of time a Merkle inclusion proof remains valid in the cache.
const MERKLE_PROOF_VALIDITY_SECONDS: u64 = 60 * 15;

#[uniffi::export]
impl Authenticator {
    /// Initializes storage using the authenticator's leaf index.
    ///
    /// # Errors
    ///
    /// Returns an error if the leaf index is invalid or storage initialization fails.
    pub fn init_storage(&self, now: u64) -> Result<(), WalletKitError> {
        self.store.init(self.leaf_index(), now)?;
        Ok(())
    }
}

impl Authenticator {
    /// Fetches a [`MerkleInclusionProof`] from the indexer, or from cache if it's available and fresh.
    ///
    /// # Errors
    ///
    /// Returns an error if fetching or caching the proof fails.
    #[allow(dead_code)] // TODO: Temporary while this gets integrated
    async fn fetch_inclusion_proof_with_cache(
        &self,
        now: u64,
    ) -> Result<
        (MerkleInclusionProof<TREE_DEPTH>, AuthenticatorPublicKeySet),
        WalletKitError,
    > {
        // If there is a cached inclusion proof, return it
        if let Some(bytes) = self.store.merkle_cache_get(now)? {
            if let Some(cached) = CachedInclusionProof::deserialize(&bytes) {
                if cached.inclusion_proof.leaf_index == self.leaf_index() {
                    return Ok((cached.inclusion_proof, cached.authenticator_keyset));
                }
            }
        }

        // Otherwise, fetch from the indexer and cache it
        let (inclusion_proof, authenticator_keyset) =
            self.inner.fetch_inclusion_proof().await?;
        let payload = CachedInclusionProof {
            inclusion_proof: inclusion_proof.clone(),
            authenticator_keyset: authenticator_keyset.clone(),
        };
        let payload = payload.serialize()?;

        if let Err(e) =
            self.store
                .merkle_cache_put(payload, now, MERKLE_PROOF_VALIDITY_SECONDS)
        {
            log::error!("Failed to cache Merkle inclusion proof: {e}");
        }

        Ok((inclusion_proof, authenticator_keyset))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedInclusionProof {
    inclusion_proof: MerkleInclusionProof<TREE_DEPTH>,
    authenticator_keyset: AuthenticatorPublicKeySet,
}

impl CachedInclusionProof {
    fn serialize(&self) -> Result<Vec<u8>, WalletKitError> {
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(self, &mut bytes).map_err(|err| {
            WalletKitError::SerializationError {
                error: err.to_string(),
            }
        })?;
        Ok(bytes)
    }

    fn deserialize(bytes: &[u8]) -> Option<Self> {
        ciborium::de::from_reader(bytes).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::tests_utils::{
        cleanup_test_storage, temp_root_path, InMemoryStorageProvider,
    };
    use crate::storage::CredentialStore;
    use world_id_core::FieldElement;

    #[test]
    fn test_cached_inclusion_round_trip() {
        let root = temp_root_path();
        let provider = InMemoryStorageProvider::new(&root);
        let store = CredentialStore::from_provider(&provider).expect("store");
        store.init(42, 100).expect("init storage");

        let siblings = [FieldElement::from(0u64); TREE_DEPTH];
        let root_fe = FieldElement::from(123u64);
        let inclusion_proof = MerkleInclusionProof::new(root_fe, 42, siblings);
        let authenticator_keyset =
            AuthenticatorPublicKeySet::new(None).expect("key set");
        let payload = CachedInclusionProof {
            inclusion_proof,
            authenticator_keyset,
        };
        let payload_bytes = payload.serialize().expect("serialize");

        store
            .merkle_cache_put(payload_bytes, 100, 60)
            .expect("cache put");
        let now = 110;
        let cached = store
            .merkle_cache_get(now)
            .expect("cache get")
            .expect("cache hit");
        let decoded = CachedInclusionProof::deserialize(&cached).expect("decode");
        assert_eq!(decoded.inclusion_proof.leaf_index, 42);
        assert_eq!(decoded.inclusion_proof.root, root_fe);
        assert_eq!(decoded.authenticator_keyset.len(), 0);
        cleanup_test_storage(&root);
    }
}
