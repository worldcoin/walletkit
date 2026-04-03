use world_id_core::primitives::merkle::AccountInclusionProof;
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

    /// Permanently destroys all credential storage data.
    ///
    /// Removes the encryption keys, vault database, and cache database.
    /// After this call the authenticator can no longer generate proofs or
    /// access stored credentials. Intended for logout or account deletion.
    ///
    /// # Errors
    ///
    /// Returns an error if the storage destruction fails.
    pub fn destroy_storage(&self) -> Result<(), WalletKitError> {
        self.store.destroy_storage()?;
        Ok(())
    }
}

impl Authenticator {
    /// Fetches a [`MerkleInclusionProof`] from the indexer, or from cache if it's available and fresh.
    ///
    /// # Errors
    ///
    /// Returns an error if fetching or caching the proof fails.
    #[tracing::instrument(
        target = "walletkit_latency",
        name = "indexer_inclusion_proof",
        skip_all
    )]
    pub(crate) async fn fetch_inclusion_proof_with_cache(
        &self,
        now: u64,
    ) -> Result<AccountInclusionProof<TREE_DEPTH>, WalletKitError> {
        // If there is a cached inclusion proof, return it
        if let Some(account_inclusion_proof) = self.store.merkle_cache_get(now)? {
            return Ok(account_inclusion_proof);
        }

        // Otherwise, fetch from the indexer and cache it
        let account_inclusion_proof = self.inner.fetch_inclusion_proof().await?;

        if let Err(e) = self.store.merkle_cache_put(
            &account_inclusion_proof,
            now,
            MERKLE_PROOF_VALIDITY_SECONDS,
        ) {
            tracing::error!("Failed to cache Merkle inclusion proof: {e}");
        }

        Ok(account_inclusion_proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::tests_utils::{
        cleanup_test_storage, temp_root_path, InMemoryStorageProvider,
    };
    use crate::storage::CredentialStore;
    use world_id_core::primitives::authenticator::AuthenticatorPublicKeySet;
    use world_id_core::primitives::merkle::MerkleInclusionProof;
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
        let authenticator_pubkeys =
            AuthenticatorPublicKeySet::new(vec![]).expect("key set");
        let account_inclusion_proof = AccountInclusionProof {
            inclusion_proof,
            authenticator_pubkeys,
        };

        store
            .merkle_cache_put(&account_inclusion_proof, 100, 60)
            .expect("cache put");
        let now = 110;
        let decoded = store
            .merkle_cache_get(now)
            .expect("cache get")
            .expect("cache hit");
        assert_eq!(decoded.inclusion_proof.leaf_index, 42);
        assert_eq!(decoded.inclusion_proof.root, root_fe);
        assert_eq!(decoded.authenticator_pubkeys.len(), 0);
        cleanup_test_storage(&root);
    }
}
