use std::sync::Arc;

use serde::{Deserialize, Serialize};
use world_id_core::primitives::authenticator::AuthenticatorPublicKeySet;
use world_id_core::primitives::merkle::MerkleInclusionProof;
use world_id_core::primitives::TREE_DEPTH;
use world_id_core::OnchainKeyRepresentable;

use crate::error::WalletKitError;
use crate::storage::CredentialStore;

use super::utils::{leaf_index_to_u64, parse_fixed_bytes, u256_to_hex};
use super::Authenticator;

/// Buffer cached proofs to remain valid during on-chain verification.
const MERKLE_PROOF_VALIDITY_BUFFER_SECS: u64 = 120;

#[uniffi::export(async_runtime = "tokio")]
impl Authenticator {
    /// Initializes storage using the authenticator's leaf index.
    ///
    /// # Errors
    ///
    /// Returns an error if the leaf index is invalid or storage initialization fails.
    #[allow(clippy::needless_pass_by_value)]
    pub fn init_storage(
        &self,
        storage: Arc<CredentialStore>,
        now: u64,
    ) -> Result<(), WalletKitError> {
        let leaf_index = leaf_index_to_u64(&self.leaf_index())?;
        storage.init(leaf_index, now)?;
        Ok(())
    }

    /// Fetches an inclusion proof, using the storage cache when possible.
    ///
    /// The cached payload uses `CachedInclusionProof` CBOR encoding and is keyed by
    /// (`registry_kind`, `root`, `leaf_index`).
    ///
    /// Returns the decoded proof with hex-encoded field elements and compressed
    /// authenticator public keys.
    ///
    /// # Errors
    ///
    /// Returns an error if fetching or caching the proof fails.
    #[allow(clippy::future_not_send)]
    pub async fn fetch_inclusion_proof_cached(
        &self,
        storage: Arc<CredentialStore>,
        registry_kind: u8,
        root: Vec<u8>,
        now: u64,
        ttl_seconds: u64,
    ) -> Result<InclusionProofPayload, WalletKitError> {
        let root = parse_fixed_bytes::<32>(root, "root")?;
        let valid_before = now.saturating_add(MERKLE_PROOF_VALIDITY_BUFFER_SECS);
        if let Some(bytes) =
            storage.merkle_cache_get(registry_kind, root.to_vec(), valid_before)?
        {
            if let Some(cached) = CachedInclusionProof::deserialize(&bytes) {
                return inclusion_proof_payload_from_cached(&cached);
            }
        }

        let (proof, key_set) = self.0.fetch_inclusion_proof().await?;
        let payload = CachedInclusionProof {
            proof: proof.clone(),
            authenticator_pubkeys: key_set,
        };
        let payload_bytes = payload.serialize()?;
        let proof_root = {
            let mut bytes = Vec::new();
            proof.root.serialize_as_bytes(&mut bytes)?;
            parse_fixed_bytes::<32>(bytes, "field_element")?
        };
        if proof_root != root {
            return Err(WalletKitError::InvalidInput {
                attribute: "root".to_string(),
                reason: "fetched proof root does not match requested root".to_string(),
            });
        }
        storage.merkle_cache_put(
            registry_kind,
            root.to_vec(),
            payload_bytes,
            now,
            ttl_seconds,
        )?;
        // FIXME: this requires a refactor. deliberately panicking because it should not be used yet.
        todo!("this requires refactoring for the proof caching");
        //inclusion_proof_payload_from_cached(&payload)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedInclusionProof {
    proof: MerkleInclusionProof<TREE_DEPTH>,
    authenticator_pubkeys: AuthenticatorPublicKeySet,
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

#[derive(Debug, Clone, uniffi::Record)]
pub struct InclusionProofPayload {
    /// Merkle root as hex string.
    pub root: String,
    /// Leaf index for the account.
    pub leaf_index: u64,
    /// Sibling path as hex strings.
    pub siblings: Vec<String>,
    /// Compressed authenticator public keys as hex strings.
    pub authenticator_pubkeys: Vec<String>,
}

fn inclusion_proof_payload_from_cached(
    payload: &CachedInclusionProof,
) -> Result<InclusionProofPayload, WalletKitError> {
    let authenticator_pubkeys = payload
        .authenticator_pubkeys
        .iter()
        .map(|pk| {
            let encoded = pk.to_ethereum_representation().map_err(|err| {
                WalletKitError::Generic {
                    error: format!("failed to encode authenticator pubkey: {err}"),
                }
            })?;
            Ok(u256_to_hex(encoded))
        })
        .collect::<Result<Vec<_>, WalletKitError>>()?;

    Ok(InclusionProofPayload {
        root: payload.proof.root.to_string(),
        leaf_index: payload.proof.leaf_index,
        siblings: payload
            .proof
            .siblings
            .iter()
            .map(std::string::ToString::to_string)
            .collect(),
        authenticator_pubkeys,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::tests_utils::InMemoryStorageProvider;
    use crate::storage::CredentialStore;
    use std::fs;
    use std::path::{Path, PathBuf};
    use uuid::Uuid;
    use world_id_core::FieldElement;

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
        let store = CredentialStore::from_provider(&provider).expect("store");
        store.init(42, 100).expect("init storage");

        let siblings = [FieldElement::from(0u64); TREE_DEPTH];
        let root_fe = FieldElement::from(123u64);
        let proof = MerkleInclusionProof::new(root_fe, 42, siblings);
        let key_set = AuthenticatorPublicKeySet::new(None).expect("key set");
        let payload = CachedInclusionProof {
            proof: proof.clone(),
            authenticator_pubkeys: key_set,
        };
        let payload_bytes = payload.serialize().expect("serialize");
        let root_bytes: [u8; 32] = {
            let mut bytes = Vec::new();
            proof
                .root
                .serialize_as_bytes(&mut bytes)
                .expect("serialize field element");
            parse_fixed_bytes::<32>(bytes, "field_element")
                .expect("field element bytes")
        };

        store
            .merkle_cache_put(1, root_bytes.to_vec(), payload_bytes, 100, 60)
            .expect("cache put");
        let valid_before = 110;
        let cached = store
            .merkle_cache_get(1, root_bytes.to_vec(), valid_before)
            .expect("cache get")
            .expect("cache hit");
        let decoded = CachedInclusionProof::deserialize(&cached).expect("decode");
        assert_eq!(decoded.proof.leaf_index, 42);
        assert_eq!(decoded.proof.root, root_fe);
        assert_eq!(decoded.authenticator_pubkeys.len(), 0);
        cleanup_storage(&root);
    }
}
