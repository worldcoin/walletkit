use std::sync::Arc;

use serde::{Deserialize, Serialize};
use world_id_core::primitives::authenticator::AuthenticatorPublicKeySet;
use world_id_core::primitives::merkle::MerkleInclusionProof;
use world_id_core::primitives::TREE_DEPTH;
use world_id_core::{requests::ProofRequest, Credential, FieldElement, OnchainKeyRepresentable};

use crate::error::WalletKitError;
use crate::storage::{CredentialStore, ReplayGuardKind, ReplayGuardResult};
use crate::U256Wrapper;

use super::Authenticator;
use super::utils::{
    field_element_to_bytes, leaf_index_to_u64, parse_fixed_bytes, u256_to_hex,
};

/// Buffer cached proofs to remain valid during on-chain verification.
const MERKLE_PROOF_VALIDITY_BUFFER_SECS: u64 = 120;

#[uniffi::export(async_runtime = "tokio")]
impl Authenticator {
    /// Initializes storage using the authenticator's leaf index.
    ///
    /// # Errors
    ///
    /// Returns an error if the leaf index is invalid or storage initialization fails.
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
            if let Some(cached) = deserialize_inclusion_proof(&bytes) {
                return inclusion_proof_payload_from_cached(&cached);
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
            proof_root.to_vec(),
            payload_bytes.clone(),
            now,
            ttl_seconds,
        )?;
        inclusion_proof_payload_from_cached(&payload)
    }

    /// Generates a proof and enforces replay safety via storage.
    ///
    /// The proof request and credential are supplied as JSON strings.
    ///
    /// # Errors
    ///
    /// Returns an error if the proof generation or storage update fails.
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::future_not_send)]
    pub async fn generate_proof_with_replay_guard(
        &self,
        storage: Arc<CredentialStore>,
        proof_request_json: &str,
        credential_json: &str,
        credential_sub_blinding_factor: &U256Wrapper,
        request_id: Vec<u8>,
        now: u64,
        ttl_seconds: u64,
    ) -> Result<ReplayGuardResult, WalletKitError> {
        let proof_request =
            ProofRequest::from_json(proof_request_json).map_err(|err| {
                WalletKitError::InvalidInput {
                    attribute: "proof_request".to_string(),
                    reason: err.to_string(),
                }
            })?;
        let credential: Credential =
            serde_json::from_str(credential_json).map_err(|err| {
                WalletKitError::InvalidInput {
                    attribute: "credential".to_string(),
                    reason: err.to_string(),
                }
            })?;
        let request_id = parse_fixed_bytes::<32>(request_id, "request_id")?;
        let credential_sub_blinding_factor = FieldElement::try_from(
            credential_sub_blinding_factor.0,
        )
        .map_err(|err| WalletKitError::InvalidInput {
            attribute: "credential_sub_blinding_factor".to_string(),
            reason: err.to_string(),
        })?;

        if let Some(bytes) = storage
            .replay_guard_get(request_id.to_vec(), now)
            .map_err(WalletKitError::from)?
        {
            return Ok(ReplayGuardResult {
                kind: ReplayGuardKind::Replay,
                bytes,
            });
        }
        let prepared = self
            .0
            .prepare_proof(proof_request, credential, credential_sub_blinding_factor)
            .await?;
        let nullifier_bytes = field_element_to_bytes(prepared.nullifier());
        storage
            .replay_guard_reserve(
                request_id.to_vec(),
                nullifier_bytes.to_vec(),
                now,
                ttl_seconds,
            )
            .map_err(WalletKitError::from)?;

        let (proof, nullifier) = self.0.generate_proof_with_prepared(prepared)?;
        let proof_bytes = serialize_proof_package(&proof, nullifier)?;
        storage
            .replay_guard_finalize(request_id.to_vec(), proof_bytes, now, ttl_seconds)
            .map_err(WalletKitError::from)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedInclusionProof {
    proof: MerkleInclusionProof<TREE_DEPTH>,
    authenticator_pubkeys: AuthenticatorPublicKeySet,
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

fn serialize_inclusion_proof(
    payload: &CachedInclusionProof,
) -> Result<Vec<u8>, WalletKitError> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(payload, &mut bytes).map_err(|err| {
        WalletKitError::SerializationError {
            error: err.to_string(),
        }
    })?;
    Ok(bytes)
}

fn deserialize_inclusion_proof(bytes: &[u8]) -> Option<CachedInclusionProof> {
    ciborium::de::from_reader(bytes).ok()
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
                    error: format!(
                        "failed to encode authenticator pubkey: {err}"
                    ),
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
            .map(|s| s.to_string())
            .collect(),
        authenticator_pubkeys,
    })
}
fn serialize_proof_package(
    proof: &impl Serialize,
    nullifier: FieldElement,
) -> Result<Vec<u8>, WalletKitError> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(&(proof, nullifier), &mut bytes).map_err(|err| {
        WalletKitError::SerializationError {
            error: err.to_string(),
        }
    })?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::tests_utils::InMemoryStorageProvider;
    use crate::storage::CredentialStore;
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
        let payload_bytes = serialize_inclusion_proof(&payload).expect("serialize");
        let root_bytes = field_element_to_bytes(proof.root);

        store
            .merkle_cache_put(1, root_bytes.to_vec(), payload_bytes, 100, 60)
            .expect("cache put");
        let valid_before = 110;
        let cached = store
            .merkle_cache_get(1, root_bytes.to_vec(), valid_before)
            .expect("cache get")
            .expect("cache hit");
        let decoded = deserialize_inclusion_proof(&cached).expect("decode");
        assert_eq!(decoded.proof.leaf_index, 42);
        assert_eq!(decoded.proof.root, root_fe);
        assert_eq!(decoded.authenticator_pubkeys.len(), 0);
        cleanup_storage(&root);
    }
}
