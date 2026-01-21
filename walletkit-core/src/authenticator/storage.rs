use std::convert::TryFrom;

use serde::{Deserialize, Serialize};
use world_id_core::primitives::authenticator::AuthenticatorPublicKeySet;
use world_id_core::primitives::merkle::MerkleInclusionProof;
use world_id_core::primitives::TREE_DEPTH;
use world_id_core::{types::RpRequest, Credential, FieldElement};

use crate::error::WalletKitError;
use crate::storage::{CredentialStorage, ProofDisclosureResult, RequestId};

use super::Authenticator;

impl Authenticator {
    /// Returns the leaf index for the holder's World ID account.
    ///
    /// # Errors
    ///
    /// Returns an error if the leaf index does not fit in a `u64`.
    pub fn leaf_index(&self) -> Result<u64, WalletKitError> {
        let value = self.0.account_id();
        u64::try_from(value).map_err(|_| WalletKitError::InvalidInput {
            attribute: "leaf_index".to_string(),
            reason: "leaf index does not fit in u64".to_string(),
        })
    }

    /// Initializes storage using the authenticator's leaf index.
    pub fn init_storage(
        &self,
        storage: &mut dyn CredentialStorage,
        now: u64,
    ) -> Result<(), WalletKitError> {
        let leaf_index = self.leaf_index()?;
        storage.init(leaf_index, now)?;
        Ok(())
    }

    /// Fetches an inclusion proof, using the storage cache when possible.
    ///
    /// The cached payload uses `AccountInclusionProof` serialization and is keyed by
    /// (`registry_kind`, `root`, `leaf_index`).
    pub async fn fetch_inclusion_proof_cached(
        &self,
        storage: &mut dyn CredentialStorage,
        registry_kind: u8,
        root: [u8; 32],
        now: u64,
        ttl_seconds: u64,
    ) -> Result<
        (MerkleInclusionProof<TREE_DEPTH>, AuthenticatorPublicKeySet),
        WalletKitError,
    > {
        if let Some(bytes) = storage.merkle_cache_get(registry_kind, root, now)? {
            if let Some(cached) = deserialize_inclusion_proof(&bytes) {
                return Ok((cached.proof, cached.authenticator_pubkeys));
            }
        }

        let (proof, key_set) = self.0.fetch_inclusion_proof().await?;
        let payload = CachedInclusionProof {
            proof: proof.clone(),
            authenticator_pubkeys: key_set.clone(),
        };
        let payload_bytes = serialize_inclusion_proof(&payload)?;
        let proof_root = field_element_to_bytes(proof.root);
        storage.merkle_cache_put(
            registry_kind,
            proof_root,
            payload_bytes,
            now,
            ttl_seconds,
        )?;
        Ok((proof, key_set))
    }

    /// Generates a proof and enforces replay safety via storage.
    #[allow(clippy::too_many_arguments)]
    pub async fn generate_proof_with_disclosure(
        &self,
        storage: &mut dyn CredentialStorage,
        message_hash: FieldElement,
        rp_request: RpRequest,
        credential: Credential,
        request_id: RequestId,
        now: u64,
        ttl_seconds: u64,
    ) -> Result<ProofDisclosureResult, WalletKitError> {
        let (proof, nullifier) = self
            .0
            .generate_proof(message_hash, rp_request, credential)
            .await?;
        let proof_bytes = serialize_proof_package(&proof, nullifier)?;
        let nullifier_bytes = field_element_to_bytes(nullifier);
        storage
            .begin_proof_disclosure(
                request_id,
                nullifier_bytes,
                proof_bytes,
                now,
                ttl_seconds,
            )
            .map_err(WalletKitError::from)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedInclusionProof {
    proof: MerkleInclusionProof<TREE_DEPTH>,
    authenticator_pubkeys: AuthenticatorPublicKeySet,
}

fn serialize_inclusion_proof(
    payload: &CachedInclusionProof,
) -> Result<Vec<u8>, WalletKitError> {
    bincode::serialize(payload).map_err(|err| WalletKitError::SerializationError {
        error: err.to_string(),
    })
}

fn deserialize_inclusion_proof(bytes: &[u8]) -> Option<CachedInclusionProof> {
    bincode::deserialize(bytes).ok()
}

fn field_element_to_bytes(value: FieldElement) -> [u8; 32] {
    let value: ruint::aliases::U256 = value.into();
    value.to_be_bytes::<32>()
}
fn serialize_proof_package(
    proof: &impl Serialize,
    nullifier: FieldElement,
) -> Result<Vec<u8>, WalletKitError> {
    bincode::serialize(&(proof, nullifier)).map_err(|err| {
        WalletKitError::SerializationError {
            error: err.to_string(),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::tests_utils::InMemoryStorageProvider;
    use crate::storage::{CredentialStorage, CredentialStore};
    use std::fs;
    use std::path::{Path, PathBuf};
    use uuid::Uuid;

    fn temp_root() -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!("walletkit-auth-storage-{}", Uuid::new_v4()));
        path
    }

    fn cleanup_storage(root: &Path) {
        let paths = crate::storage::StoragePaths::new(root);
        let vault = paths.vault_db_path();
        let cache = paths.cache_db_path();
        let lock = paths.lock_path();
        let _ = fs::remove_file(&vault);
        let _ = fs::remove_file(vault.with_extension("sqlite-wal"));
        let _ = fs::remove_file(vault.with_extension("sqlite-shm"));
        let _ = fs::remove_file(&cache);
        let _ = fs::remove_file(cache.with_extension("sqlite-wal"));
        let _ = fs::remove_file(cache.with_extension("sqlite-shm"));
        let _ = fs::remove_file(lock);
        let _ = fs::remove_dir_all(paths.worldid_dir());
        let _ = fs::remove_dir_all(paths.root());
    }

    #[test]
    fn test_cached_inclusion_round_trip() {
        let root = temp_root();
        let provider = InMemoryStorageProvider::new(&root);
        let mut store = CredentialStore::from_provider(&provider).expect("store");
        store.init(42, 100).expect("init storage");

        let siblings = [FieldElement::from(0u64); TREE_DEPTH];
        let root_fe = FieldElement::from(123u64);
        let proof = MerkleInclusionProof::new(root_fe, 42, siblings);
        let key_set = AuthenticatorPublicKeySet::new(None).expect("key set");
        let payload = CachedInclusionProof {
            proof: proof.clone(),
            authenticator_pubkeys: key_set,
        };
        let payload_bytes = serialize_inclusion_proof(&payload).expect("serialize");
        let root_bytes = field_element_to_bytes(proof.root);

        store
            .merkle_cache_put(1, root_bytes, payload_bytes, 100, 60)
            .expect("cache put");
        let cached = store
            .merkle_cache_get(1, root_bytes, 110)
            .expect("cache get")
            .expect("cache hit");
        let decoded = deserialize_inclusion_proof(&cached).expect("decode");
        assert_eq!(decoded.proof.account_id, 42);
        assert_eq!(decoded.proof.root, root_fe);
        assert_eq!(decoded.authenticator_pubkeys.len(), 0);
        cleanup_storage(&root);
    }
}
