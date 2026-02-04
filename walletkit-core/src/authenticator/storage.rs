use std::sync::Arc;

use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use world_id_core::primitives::authenticator::AuthenticatorPublicKeySet;
use world_id_core::primitives::merkle::MerkleInclusionProof;
use world_id_core::primitives::TREE_DEPTH;
use world_id_core::{
    requests::ProofRequest, Credential, FieldElement, OnchainKeyRepresentable,
};

use crate::error::WalletKitError;
use crate::storage::{CredentialStore, ReplayGuardKind, ReplayGuardResult};
use crate::types::ProofResponse;
use crate::U256Wrapper;

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
        inclusion_proof_payload_from_cached(&payload)
    }

    /// Generates a proof and enforces replay safety via storage.
    ///
    /// The proof request and credential are supplied as JSON strings.
    ///
    /// # Errors
    ///
    /// Returns an error if the proof generation or storage update fails.
    #[allow(clippy::future_not_send)]
    pub async fn generate_proof_with_replay_guard(
        &self,
        storage: Arc<CredentialStore>, // FIXME: should be in the constructor
        proof_request_json: &str,      // FIXME: should be typed
        now: Option<u64>,
    ) -> Result<ProofResponse, WalletKitError> {
        let proof_request =
            ProofRequest::from_json(proof_request_json).map_err(|err| {
                WalletKitError::InvalidInput {
                    attribute: "proof_request".to_string(),
                    reason: err.to_string(),
                }
            })?;

        let now = match now {
            Some(n) => n,
            None => {
                let start = std::time::SystemTime::now();
                start
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|e| WalletKitError::Generic {
                        error: format!("critical. unable to determine SystemTime: {e}"),
                    })?
                    .as_secs()
            }
        };

        // First check if the request can be fulfilled and which credentials should be used
        let credential_list = storage.list_credentials(None, now)?;
        let credential_list = credential_list
            .into_iter()
            .map(|cred| cred.issuer_schema_id.clone().to_string())
            .collect::<std::collections::HashSet<_>>();
        let credentials_to_prove = proof_request
            .credentials_to_prove(&credential_list)
            .ok_or(WalletKitError::Generic {
                // FIXME: this should return a ProofResponse but with an error attribute
                error: "unfulfillable request".to_string(),
            })?;

        // Next, generate the nullifier and check the replay guard
        let nullifier = self.0.generate_nullifier(&proof_request).await?;

        if let Some(bytes) = storage
            .replay_guard_get(request_id.to_vec(), now)
            .map_err(WalletKitError::from)?
        {
            return Ok(ReplayGuardResult {
                kind: ReplayGuardKind::Replay,
                bytes,
            });
        }
        for request_item in credentials_to_prove {
            // TODO
        }

        let (proof, nullifier) = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                self.0
                    .generate_proof(
                        proof_request,
                        credential,
                        credential_sub_blinding_factor,
                    )
                    .await
            })
        })?;
        let proof_bytes = serialize_proof_package(&proof, nullifier)?;
        let request_item = proof_request
            .find_request_by_issuer_schema_id(credential.issuer_schema_id)
            .ok_or_else(|| WalletKitError::InvalidInput {
                attribute: "proof_request".to_string(),
                reason: "no matching request item for credential issuer_schema_id"
                    .to_string(),
            })?;
        let oprf_nullifier = self.0.generate_nullifier(&proof_request).await?;
        let session_id_r_seed = FieldElement::random(&mut OsRng);
        let response_item = self.0.generate_single_proof(
            oprf_nullifier,
            request_item,
            &credential,
            credential_sub_blinding_factor,
            session_id_r_seed,
            proof_request.session_id,
            proof_request.created_at,
        )?;
        let proof_bytes = serialize_proof(&response_item.proof)?;
        let nullifier_bytes = {
            let mut bytes = Vec::new();
            response_item.nullifier.serialize_as_bytes(&mut bytes)?;
            parse_fixed_bytes::<32>(bytes, "field_element")?
        };
        storage
            .begin_replay_guard(
                request_id.to_vec(),
                nullifier_bytes.to_vec(),
                proof_bytes,
                now,
                ttl_seconds,
            )
            .map_err(WalletKitError::from);

        todo!("not fully implemented");
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
fn serialize_proof(proof: &impl Serialize) -> Result<Vec<u8>, WalletKitError> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(proof, &mut bytes).map_err(|err| {
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
