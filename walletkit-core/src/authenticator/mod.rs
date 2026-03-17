//! The Authenticator is the main component with which users interact with the World ID Protocol.

use crate::{
    defaults::DefaultConfig, error::WalletKitError,
    primitives::ParseFromForeignBinding, Environment, FieldElement, Region,
};
use alloy_primitives::Address;
use ruint_uniffi::Uint256;
use std::sync::Arc;
use world_id_core::{
    api_types::{GatewayErrorCode, GatewayRequestState, GatewayStatusResponse},
    primitives::Config,
    Authenticator as CoreAuthenticator, Credential as CoreCredential, EdDSAPublicKey,
    InitializingAuthenticator as CoreInitializingAuthenticator,
};

#[cfg(feature = "storage")]
use world_id_core::{
    requests::{ProofResponse as CoreProofResponse, ResponseItem},
    FieldElement as CoreFieldElement,
};

#[cfg(feature = "storage")]
use crate::storage::{CredentialStore, StoragePaths};

#[cfg(feature = "storage")]
use crate::requests::{ProofRequest, ProofResponse};

#[cfg(feature = "storage")]
use rand::rngs::OsRng;

#[cfg(feature = "storage")]
mod with_storage;

type Groth16Materials = (
    Arc<world_id_core::proof::CircomGroth16Material>,
    Arc<world_id_core::proof::CircomGroth16Material>,
);

#[cfg(not(feature = "storage"))]
/// Loads embedded Groth16 query/nullifier material for authenticator initialization.
///
/// # Errors
/// Returns an error if embedded material cannot be loaded or verified.
fn load_embedded_materials() -> Result<Groth16Materials, WalletKitError> {
    let query_material =
        world_id_core::proof::load_embedded_query_material().map_err(|error| {
            WalletKitError::Groth16MaterialEmbeddedLoad {
                error: error.to_string(),
            }
        })?;
    let nullifier_material = world_id_core::proof::load_embedded_nullifier_material()
        .map_err(|error| {
        WalletKitError::Groth16MaterialEmbeddedLoad {
            error: error.to_string(),
        }
    })?;

    Ok((Arc::new(query_material), Arc::new(nullifier_material)))
}

#[cfg(feature = "storage")]
/// Loads cached Groth16 query/nullifier material from the provided storage paths.
///
/// # Errors
/// Returns an error if cached material cannot be loaded or verified.
fn load_cached_materials(
    paths: &StoragePaths,
) -> Result<Groth16Materials, WalletKitError> {
    let query_zkey = paths.query_zkey_path();
    let nullifier_zkey = paths.nullifier_zkey_path();
    let query_graph = paths.query_graph_path();
    let nullifier_graph = paths.nullifier_graph_path();

    let query_material = load_query_material_from_cache(&query_zkey, &query_graph)?;
    let nullifier_material =
        load_nullifier_material_from_cache(&nullifier_zkey, &nullifier_graph)?;

    Ok((Arc::new(query_material), Arc::new(nullifier_material)))
}

#[cfg(feature = "storage")]
/// Loads cached query material from zkey/graph paths.
///
/// # Errors
/// Returns an error if the cached query material cannot be loaded or verified.
fn load_query_material_from_cache(
    query_zkey: &std::path::Path,
    query_graph: &std::path::Path,
) -> Result<world_id_core::proof::CircomGroth16Material, WalletKitError> {
    world_id_core::proof::load_query_material_from_paths(query_zkey, query_graph)
        .map_err(|error| WalletKitError::Groth16MaterialCacheInvalid {
            path: format!(
                "{} and {}",
                query_zkey.to_string_lossy(),
                query_graph.to_string_lossy()
            ),
            error: error.to_string(),
        })
}

#[cfg(feature = "storage")]
#[expect(
    clippy::unnecessary_wraps,
    reason = "Temporary wrapper until world-id-core returns Result for nullifier path loader"
)]
/// Loads cached nullifier material from zkey/graph paths.
///
/// # Errors
/// This currently mirrors a panicking upstream API and does not return an error path yet.
/// It is intentionally wrapped in `Result` for forward compatibility with upstream.
fn load_nullifier_material_from_cache(
    nullifier_zkey: &std::path::Path,
    nullifier_graph: &std::path::Path,
) -> Result<world_id_core::proof::CircomGroth16Material, WalletKitError> {
    // TODO: Switch to error mapping once world-id-core exposes
    // `load_nullifier_material_from_paths` as `Result` instead of panicking.
    Ok(world_id_core::proof::load_nullifier_material_from_paths(
        nullifier_zkey,
        nullifier_graph,
    ))
}

/// Parses a compressed off-chain `EdDSA` public key from a 32-byte little-endian byte slice.
///
/// # Errors
/// Returns an error if the bytes are not exactly 32 bytes or cannot be decompressed.
fn parse_compressed_pubkey(bytes: &[u8]) -> Result<EdDSAPublicKey, WalletKitError> {
    let compressed: [u8; 32] =
        bytes.try_into().map_err(|_| WalletKitError::InvalidInput {
            attribute: "new_authenticator_pubkey_bytes".to_string(),
            reason: format!(
                "Expected 32 bytes for compressed public key, got {}",
                bytes.len()
            ),
        })?;
    EdDSAPublicKey::from_compressed_bytes(compressed).map_err(|e| {
        WalletKitError::InvalidInput {
            attribute: "new_authenticator_pubkey_bytes".to_string(),
            reason: format!("Invalid compressed public key: {e}"),
        }
    })
}

/// The Authenticator is the main component with which users interact with the World ID Protocol.
#[derive(Debug, uniffi::Object)]
pub struct Authenticator {
    inner: CoreAuthenticator,
    #[cfg(feature = "storage")]
    store: Arc<CredentialStore>,
}

#[uniffi::export(async_runtime = "tokio")]
impl Authenticator {
    /// Returns the packed account data for the holder's World ID.
    ///
    /// The packed account data is a 256 bit integer which includes the user's leaf index, their recovery counter,
    /// and their pubkey id/commitment.
    #[must_use]
    pub fn packed_account_data(&self) -> Uint256 {
        self.inner.packed_account_data.into()
    }

    /// Returns the leaf index for the holder's World ID.
    ///
    /// This is the index in the Merkle tree where the holder's World ID account is registered. It
    /// should only be used inside the authenticator and never shared.
    #[must_use]
    pub fn leaf_index(&self) -> u64 {
        self.inner.leaf_index()
    }

    /// Returns the Authenticator's `onchain_address`.
    ///
    /// See `world_id_core::Authenticator::onchain_address` for more details.
    #[must_use]
    pub fn onchain_address(&self) -> String {
        self.inner.onchain_address().to_string()
    }

    /// Returns the packed account data for the holder's World ID fetching it from the on-chain registry.
    ///
    /// # Errors
    /// Will error if the provided RPC URL is not valid or if there are RPC call failures.
    pub async fn get_packed_account_data_remote(
        &self,
    ) -> Result<Uint256, WalletKitError> {
        let client = reqwest::Client::new(); // TODO: reuse client
        let packed_account_data = CoreAuthenticator::get_packed_account_data(
            self.inner.onchain_address(),
            self.inner.registry().as_deref(),
            &self.inner.config,
            &client,
        )
        .await?;
        Ok(packed_account_data.into())
    }

    /// Generates a blinding factor for a Credential sub (through OPRF Nodes).
    ///
    /// See [`CoreAuthenticator::generate_credential_blinding_factor`] for more details.
    ///
    /// # Errors
    ///
    /// - Will generally error if there are network issues or if the OPRF Nodes return an error.
    /// - Raises an error if the OPRF Nodes configuration is not correctly set.
    pub async fn generate_credential_blinding_factor_remote(
        &self,
        issuer_schema_id: u64,
    ) -> Result<FieldElement, WalletKitError> {
        Ok(self
            .inner
            .generate_credential_blinding_factor(issuer_schema_id)
            .await
            .map(Into::into)?)
    }

    /// Compute the `sub` for a credential from the authenticator's leaf index and a `blinding_factor`.
    #[must_use]
    pub fn compute_credential_sub(
        &self,
        blinding_factor: &FieldElement,
    ) -> FieldElement {
        CoreCredential::compute_sub(self.inner.leaf_index(), blinding_factor.0).into()
    }

    /// Signs an arbitrary challenge with the authenticator's on-chain key.
    ///
    /// # Warning
    /// This is considered a dangerous operation because it leaks the user's on-chain key,
    /// hence its `leaf_index`. The only acceptable use is to prove the user's `leaf_index`
    /// to a Recovery Agent. The Recovery Agent is the only party beyond the user who needs
    /// to know the `leaf_index`.
    ///
    /// # Errors
    /// May error if very unexpectedly the signing process fails. Not expected.
    pub fn danger_sign_challenge(
        &self,
        challenge: &[u8],
    ) -> Result<Vec<u8>, WalletKitError> {
        let signature = self.inner.danger_sign_challenge(challenge)?;
        Ok(signature.as_bytes().to_vec())
    }

    /// Inserts a new authenticator to the account.
    ///
    /// The current authenticator signs the request to authorize adding a new authenticator.
    /// The new authenticator will be registered in the `WorldIDRegistry` contract and can
    /// subsequently sign operations on behalf of the same World ID.
    ///
    /// # Arguments
    /// * `new_authenticator_pubkey_bytes` - The compressed off-chain `EdDSA` public key of the new
    ///   authenticator (32 bytes, little-endian).
    /// * `new_authenticator_address` - The on-chain Ethereum address (hex string) of the new
    ///   authenticator.
    ///
    /// # Returns
    /// A gateway request ID that can be used with [`poll_operation_status`](Self::poll_operation_status)
    /// to track the on-chain finalization of the operation.
    ///
    /// # Errors
    /// - Will error if the compressed public key bytes are invalid or not 32 bytes.
    /// - Will error if the address string is not a valid hex address.
    /// - Will error if there are network issues communicating with the indexer or gateway.
    /// - Will error if the maximum number of authenticators has been reached.
    pub async fn insert_authenticator(
        &self,
        new_authenticator_pubkey_bytes: Vec<u8>,
        new_authenticator_address: String,
    ) -> Result<String, WalletKitError> {
        let new_address = Address::parse_from_ffi(
            &new_authenticator_address,
            "new_authenticator_address",
        )?;
        let new_pubkey = parse_compressed_pubkey(&new_authenticator_pubkey_bytes)?;
        Ok(self
            .inner
            .insert_authenticator(new_pubkey, new_address)
            .await?)
    }

    /// Updates an existing authenticator slot with a new authenticator.
    ///
    /// The current authenticator signs the request to authorize replacing the authenticator
    /// at the specified slot index.
    ///
    /// # Arguments
    /// * `old_authenticator_address` - The on-chain address (hex string) of the authenticator being replaced.
    /// * `new_authenticator_address` - The on-chain address (hex string) of the new authenticator.
    /// * `new_authenticator_pubkey_bytes` - The compressed off-chain `EdDSA` public key of the new
    ///   authenticator (32 bytes, little-endian).
    /// * `index` - The pubkey slot index of the authenticator being replaced.
    ///
    /// # Returns
    /// A gateway request ID that can be used with [`poll_operation_status`](Self::poll_operation_status).
    ///
    /// # Errors
    /// - Will error if the compressed public key bytes are invalid.
    /// - Will error if the address strings are not valid hex addresses.
    /// - Will error if the index is out of bounds.
    /// - Will error if there are network issues.
    pub async fn update_authenticator(
        &self,
        old_authenticator_address: String,
        new_authenticator_address: String,
        new_authenticator_pubkey_bytes: Vec<u8>,
        index: u32,
    ) -> Result<String, WalletKitError> {
        let old_address = Address::parse_from_ffi(
            &old_authenticator_address,
            "old_authenticator_address",
        )?;
        let new_address = Address::parse_from_ffi(
            &new_authenticator_address,
            "new_authenticator_address",
        )?;
        let new_pubkey = parse_compressed_pubkey(&new_authenticator_pubkey_bytes)?;
        Ok(self
            .inner
            .update_authenticator(old_address, new_address, new_pubkey, index)
            .await?)
    }

    /// Removes an authenticator from the account.
    ///
    /// The current authenticator signs the request to authorize removing the authenticator
    /// at the specified slot index. An authenticator can remove itself or any other authenticator
    /// on the same account.
    ///
    /// # Arguments
    /// * `authenticator_address` - The on-chain address (hex string) of the authenticator to remove.
    /// * `index` - The pubkey slot index of the authenticator being removed.
    ///
    /// # Returns
    /// A gateway request ID that can be used with [`poll_operation_status`](Self::poll_operation_status).
    ///
    /// # Errors
    /// - Will error if the address string is not a valid hex address.
    /// - Will error if the index is out of bounds or there is no authenticator at that slot.
    /// - Will error if there are network issues.
    pub async fn remove_authenticator(
        &self,
        authenticator_address: String,
        index: u32,
    ) -> Result<String, WalletKitError> {
        let auth_address =
            Address::parse_from_ffi(&authenticator_address, "authenticator_address")?;
        Ok(self.inner.remove_authenticator(auth_address, index).await?)
    }

    /// Polls the status of a gateway operation (insert, update, or remove authenticator).
    ///
    /// Use the request ID returned by [`insert_authenticator`](Self::insert_authenticator),
    /// [`update_authenticator`](Self::update_authenticator), or
    /// [`remove_authenticator`](Self::remove_authenticator) to track the operation.
    ///
    /// # Errors
    /// Will error if the network request fails or the gateway returns an error.
    pub async fn poll_operation_status(
        &self,
        request_id: String,
    ) -> Result<RegistrationStatus, WalletKitError> {
        let url = format!("{}/status/{}", self.inner.config.gateway_url(), request_id);
        let client = reqwest::Client::new(); // TODO: reuse client
        let resp = client.get(&url).send().await?;
        let status = resp.status();

        if status.is_success() {
            let body: GatewayStatusResponse = resp.json().await?;
            Ok(body.status.into())
        } else {
            let body = resp
                .text()
                .await
                .unwrap_or_else(|e| format!("Unable to read response body: {e}"));
            Err(WalletKitError::NetworkError {
                url,
                error: body,
                status: Some(status.as_u16()),
            })
        }
    }
}

#[cfg(not(feature = "storage"))]
#[uniffi::export(async_runtime = "tokio")]
impl Authenticator {
    /// Initializes a new Authenticator from a seed and with SDK defaults.
    ///
    /// The user's World ID must already be registered in the `WorldIDRegistry`,
    /// otherwise a [`WalletKitError::AccountDoesNotExist`] error will be returned.
    ///
    /// # Errors
    /// See `CoreAuthenticator::init` for potential errors.
    #[uniffi::constructor]
    pub async fn init_with_defaults(
        seed: &[u8],
        rpc_url: Option<String>,
        environment: &Environment,
        region: Option<Region>,
    ) -> Result<Self, WalletKitError> {
        let config = Config::from_environment(environment, rpc_url, region)?;
        let authenticator = CoreAuthenticator::init(seed, config).await?;
        let (query_material, nullifier_material) = load_embedded_materials()?;
        let authenticator =
            authenticator.with_proof_materials(query_material, nullifier_material);
        Ok(Self {
            inner: authenticator,
        })
    }

    /// Initializes a new Authenticator from a seed and config.
    ///
    /// The user's World ID must already be registered in the `WorldIDRegistry`,
    /// otherwise a [`WalletKitError::AccountDoesNotExist`] error will be returned.
    ///
    /// # Errors
    /// Will error if the provided seed is not valid or if the config is not valid.
    #[uniffi::constructor]
    pub async fn init(seed: &[u8], config: &str) -> Result<Self, WalletKitError> {
        let config =
            Config::from_json(config).map_err(|_| WalletKitError::InvalidInput {
                attribute: "config".to_string(),
                reason: "Invalid config".to_string(),
            })?;
        let authenticator = CoreAuthenticator::init(seed, config).await?;
        let (query_material, nullifier_material) = load_embedded_materials()?;
        let authenticator =
            authenticator.with_proof_materials(query_material, nullifier_material);
        Ok(Self {
            inner: authenticator,
        })
    }
}

#[cfg(feature = "storage")]
#[uniffi::export(async_runtime = "tokio")]
impl Authenticator {
    /// Initializes a new Authenticator from a seed and with SDK defaults.
    ///
    /// The user's World ID must already be registered in the `WorldIDRegistry`,
    /// otherwise a [`WalletKitError::AccountDoesNotExist`] error will be returned.
    ///
    /// # Errors
    /// See `CoreAuthenticator::init` for potential errors.
    #[uniffi::constructor]
    pub async fn init_with_defaults(
        seed: &[u8],
        rpc_url: Option<String>,
        environment: &Environment,
        region: Option<Region>,
        paths: &StoragePaths,
        store: Arc<CredentialStore>,
    ) -> Result<Self, WalletKitError> {
        let config = Config::from_environment(environment, rpc_url, region)?;
        let authenticator = CoreAuthenticator::init(seed, config).await?;
        let (query_material, nullifier_material) = load_cached_materials(paths)?;
        let authenticator =
            authenticator.with_proof_materials(query_material, nullifier_material);
        Ok(Self {
            inner: authenticator,
            store,
        })
    }

    /// Initializes a new Authenticator from a seed and config.
    ///
    /// The user's World ID must already be registered in the `WorldIDRegistry`,
    /// otherwise a [`WalletKitError::AccountDoesNotExist`] error will be returned.
    ///
    /// # Errors
    /// Will error if the provided seed is not valid or if the config is not valid.
    #[uniffi::constructor]
    pub async fn init(
        seed: &[u8],
        config: &str,
        paths: &StoragePaths,
        store: Arc<CredentialStore>,
    ) -> Result<Self, WalletKitError> {
        let config =
            Config::from_json(config).map_err(|_| WalletKitError::InvalidInput {
                attribute: "config".to_string(),
                reason: "Invalid config".to_string(),
            })?;

        let authenticator = CoreAuthenticator::init(seed, config).await?;
        let (query_material, nullifier_material) = load_cached_materials(paths)?;
        let authenticator =
            authenticator.with_proof_materials(query_material, nullifier_material);
        Ok(Self {
            inner: authenticator,
            store,
        })
    }

    /// Generates a proof for the given proof request.
    ///
    /// # Errors
    /// Returns an error if proof generation fails.
    pub async fn generate_proof(
        &self,
        proof_request: &ProofRequest,
        now: Option<u64>,
    ) -> Result<ProofResponse, WalletKitError> {
        let now = if let Some(n) = now {
            n
        } else {
            let start = std::time::SystemTime::now();
            start
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| WalletKitError::Generic {
                    error: format!("Critical. Unable to determine SystemTime: {e}"),
                })?
                .as_secs()
        };

        // First check if the request can be fulfilled and which credentials should be used
        let credential_list = self.store.list_credentials(None, now)?;
        let credential_list = credential_list
            .into_iter()
            .filter(|cred| !cred.is_expired)
            .map(|cred| cred.issuer_schema_id)
            .collect::<std::collections::HashSet<_>>();
        let credentials_to_prove = proof_request
            .0
            .credentials_to_prove(&credential_list)
            .ok_or(WalletKitError::UnfulfillableRequest)?;

        let (inclusion_proof, key_set) =
            self.fetch_inclusion_proof_with_cache(now).await?;

        // Next, generate the nullifier and check the replay guard
        let nullifier = self
            .inner
            .generate_nullifier(&proof_request.0, inclusion_proof, key_set)
            .await?;

        // NOTE: In a normal flow this error can not be triggered since OPRF nodes have their own
        // replay protection so the function will fail before this when attempting to generate the nullifier
        if self
            .store
            .is_nullifier_replay(nullifier.verifiable_oprf_output.output.into(), now)?
        {
            return Err(WalletKitError::NullifierReplay);
        }

        let mut responses: Vec<ResponseItem> = vec![];

        for request_item in credentials_to_prove {
            let (credential, blinding_factor) = self
                .store
                .get_credential(request_item.issuer_schema_id, now)?
                .ok_or(WalletKitError::CredentialNotIssued)?;

            let session_id_r_seed = CoreFieldElement::random(&mut OsRng); // TODO: Properly fetch session seed from cache

            let response_item = self.inner.generate_single_proof(
                nullifier.clone(),
                request_item,
                &credential,
                blinding_factor.0,
                session_id_r_seed,
                proof_request.0.session_id,
                proof_request.0.created_at,
            )?;
            responses.push(response_item);
        }

        let response = CoreProofResponse {
            id: proof_request.0.id.clone(),
            version: world_id_core::requests::RequestVersion::V1,
            responses,
            error: None,
            session_id: None, // TODO: This needs to be computed to be shareable
        };

        proof_request
            .0
            .validate_response(&response)
            .map_err(|err| WalletKitError::ResponseValidation(err.to_string()))?;

        self.store
            .replay_guard_set(nullifier.verifiable_oprf_output.output.into(), now)?;

        Ok(response.into())
    }
}

/// Registration status for a World ID being created through the gateway.
#[derive(Debug, Clone, uniffi::Enum)]
pub enum RegistrationStatus {
    /// Request queued but not yet batched.
    Queued,
    /// Request currently being batched.
    Batching,
    /// Request submitted on-chain.
    Submitted,
    /// Request finalized on-chain. The World ID is now registered.
    Finalized,
    /// Request failed during processing.
    Failed {
        /// Error message returned by the gateway.
        error: String,
        /// Specific error code, if available.
        error_code: Option<String>,
    },
}

impl From<GatewayRequestState> for RegistrationStatus {
    fn from(state: GatewayRequestState) -> Self {
        match state {
            GatewayRequestState::Queued => Self::Queued,
            GatewayRequestState::Batching => Self::Batching,
            GatewayRequestState::Submitted { .. } => Self::Submitted,
            GatewayRequestState::Finalized { .. } => Self::Finalized,
            GatewayRequestState::Failed { error, error_code } => Self::Failed {
                error,
                error_code: error_code.map(|c: GatewayErrorCode| c.to_string()),
            },
        }
    }
}

/// Represents an Authenticator in the process of being initialized.
///
/// The account is not yet registered in the `WorldIDRegistry` contract.
/// Use this for non-blocking registration flows where you want to poll the status yourself.
#[derive(uniffi::Object)]
pub struct InitializingAuthenticator(CoreInitializingAuthenticator);

#[uniffi::export(async_runtime = "tokio")]
impl InitializingAuthenticator {
    /// Registers a new World ID with SDK defaults.
    ///
    /// This returns immediately and does not wait for registration to complete.
    /// The returned `InitializingAuthenticator` can be used to poll the registration status.
    ///
    /// # Errors
    /// See `CoreAuthenticator::register` for potential errors.
    #[uniffi::constructor]
    pub async fn register_with_defaults(
        seed: &[u8],
        rpc_url: Option<String>,
        environment: &Environment,
        region: Option<Region>,
        recovery_address: Option<String>,
    ) -> Result<Self, WalletKitError> {
        let recovery_address =
            Address::parse_from_ffi_optional(recovery_address, "recovery_address")?;

        let config = Config::from_environment(environment, rpc_url, region)?;

        let initializing_authenticator =
            CoreAuthenticator::register(seed, config, recovery_address).await?;

        Ok(Self(initializing_authenticator))
    }

    /// Registers a new World ID.
    ///
    /// This returns immediately and does not wait for registration to complete.
    /// The returned `InitializingAuthenticator` can be used to poll the registration status.
    ///
    /// # Errors
    /// See `CoreAuthenticator::register` for potential errors.
    #[uniffi::constructor]
    pub async fn register(
        seed: &[u8],
        config: &str,
        recovery_address: Option<String>,
    ) -> Result<Self, WalletKitError> {
        let recovery_address =
            Address::parse_from_ffi_optional(recovery_address, "recovery_address")?;

        let config =
            Config::from_json(config).map_err(|_| WalletKitError::InvalidInput {
                attribute: "config".to_string(),
                reason: "Invalid config".to_string(),
            })?;

        let initializing_authenticator =
            CoreAuthenticator::register(seed, config, recovery_address).await?;

        Ok(Self(initializing_authenticator))
    }

    /// Polls the registration status from the gateway.
    ///
    /// # Errors
    /// Will error if the network request fails or the gateway returns an error.
    pub async fn poll_status(&self) -> Result<RegistrationStatus, WalletKitError> {
        let status = self.0.poll_status().await?;
        Ok(status.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use world_id_core::OnchainKeyRepresentable;

    fn test_pubkey(seed_byte: u8) -> EdDSAPublicKey {
        let signer =
            world_id_core::primitives::Signer::from_seed_bytes(&[seed_byte; 32])
                .unwrap();
        signer.offchain_signer_pubkey()
    }

    fn compressed_pubkey_bytes(seed_byte: u8) -> Vec<u8> {
        let pk = test_pubkey(seed_byte);
        let u256 = pk.to_ethereum_representation().unwrap();
        u256.to_le_bytes_vec()
    }

    // ── Compressed pubkey parsing ──

    #[test]
    fn test_parse_compressed_pubkey_valid() {
        let bytes = compressed_pubkey_bytes(1);
        assert_eq!(bytes.len(), 32);
        let result = parse_compressed_pubkey(&bytes);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_compressed_pubkey_wrong_length() {
        let short = vec![0u8; 16];
        let result = parse_compressed_pubkey(&short);
        assert!(matches!(
            result,
            Err(WalletKitError::InvalidInput { attribute, .. })
                if attribute == "new_authenticator_pubkey_bytes"
        ));
    }

    #[test]
    fn test_parse_compressed_pubkey_roundtrip() {
        let original = test_pubkey(42);
        let bytes = {
            let u256 = original.to_ethereum_representation().unwrap();
            u256.to_le_bytes_vec()
        };
        let recovered = parse_compressed_pubkey(&bytes).unwrap();
        assert_eq!(original.pk, recovered.pk);
    }
}

// ── Storage-dependent tests ──

#[cfg(all(test, feature = "storage"))]
mod storage_tests {
    use super::*;
    use crate::storage::cache_embedded_groth16_material;
    use crate::storage::tests_utils::{
        cleanup_test_storage, temp_root_path, InMemoryStorageProvider,
    };
    use alloy::primitives::address;

    #[tokio::test]
    async fn test_init_with_config_and_storage() {
        // Install default crypto provider for rustls
        let _ = rustls::crypto::ring::default_provider().install_default();

        let mut mock_server = mockito::Server::new_async().await;

        // Mock eth_call to return account data indicating account exists
        mock_server
            .mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": "0x0000000000000000000000000000000000000000000000000000000000000001"
                })
                .to_string(),
            )
            .create_async()
            .await;

        let seed = [2u8; 32];
        let config = Config::new(
            Some(mock_server.url()),
            480,
            address!("0x969947cFED008bFb5e3F32a25A1A2CDdf64d46fe"),
            "https://world-id-indexer.stage-crypto.worldcoin.org".to_string(),
            "https://world-id-gateway.stage-crypto.worldcoin.org".to_string(),
            vec![],
            2,
        )
        .unwrap();
        let config = serde_json::to_string(&config).unwrap();

        let root = temp_root_path();
        let provider = InMemoryStorageProvider::new(&root);
        let store = CredentialStore::from_provider(&provider).expect("store");
        store.init(42, 100).expect("init storage");
        cache_embedded_groth16_material(&store.storage_paths().expect("paths"))
            .expect("cache material");

        let paths = store.storage_paths().expect("paths");
        Authenticator::init(&seed, &config, &paths, Arc::new(store))
            .await
            .unwrap();
        drop(mock_server);
        cleanup_test_storage(&root);
    }

    #[tokio::test]
    async fn test_poll_operation_status_finalized() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/status/req_abc")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                serde_json::json!({
                    "request_id": "req_abc",
                    "kind": "insert_authenticator",
                    "status": { "state": "finalized", "tx_hash": "0x1234" }
                })
                .to_string(),
            )
            .create_async()
            .await;

        // Create an Authenticator pointing at this mock server
        let mut rpc_server = mockito::Server::new_async().await;
        rpc_server
            .mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": "0x0000000000000000000000000000000000000000000000000000000000000001"
                })
                .to_string(),
            )
            .create_async()
            .await;

        let seed = [3u8; 32];
        let config = Config::new(
            Some(rpc_server.url()),
            480,
            address!("0x969947cFED008bFb5e3F32a25A1A2CDdf64d46fe"),
            "https://unused-indexer.example.com".to_string(),
            server.url(),
            vec![],
            2,
        )
        .unwrap();
        let config = serde_json::to_string(&config).unwrap();

        let root = temp_root_path();
        let provider = InMemoryStorageProvider::new(&root);
        let store = CredentialStore::from_provider(&provider).expect("store");
        store.init(42, 100).expect("init storage");
        cache_embedded_groth16_material(&store.storage_paths().expect("paths"))
            .expect("cache material");

        let paths = store.storage_paths().expect("paths");
        let auth = Authenticator::init(&seed, &config, &paths, Arc::new(store))
            .await
            .unwrap();

        let status = auth
            .poll_operation_status("req_abc".to_string())
            .await
            .unwrap();
        assert!(matches!(status, RegistrationStatus::Finalized));

        mock.assert_async().await;
        drop(server);
        drop(rpc_server);
        cleanup_test_storage(&root);
    }

    #[tokio::test]
    async fn test_poll_operation_status_gateway_error() {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/status/req_bad")
            .with_status(500)
            .with_body("internal server error")
            .create_async()
            .await;

        let mut rpc_server = mockito::Server::new_async().await;
        rpc_server
            .mock("POST", "/")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": "0x0000000000000000000000000000000000000000000000000000000000000001"
                })
                .to_string(),
            )
            .create_async()
            .await;

        let seed = [4u8; 32];
        let config = Config::new(
            Some(rpc_server.url()),
            480,
            address!("0x969947cFED008bFb5e3F32a25A1A2CDdf64d46fe"),
            "https://unused-indexer.example.com".to_string(),
            server.url(),
            vec![],
            2,
        )
        .unwrap();
        let config = serde_json::to_string(&config).unwrap();

        let root = temp_root_path();
        let provider = InMemoryStorageProvider::new(&root);
        let store = CredentialStore::from_provider(&provider).expect("store");
        store.init(42, 100).expect("init storage");
        cache_embedded_groth16_material(&store.storage_paths().expect("paths"))
            .expect("cache material");

        let paths = store.storage_paths().expect("paths");
        let auth = Authenticator::init(&seed, &config, &paths, Arc::new(store))
            .await
            .unwrap();

        let result = auth.poll_operation_status("req_bad".to_string()).await;
        assert!(matches!(
            result,
            Err(WalletKitError::NetworkError {
                status: Some(500),
                ..
            })
        ));

        mock.assert_async().await;
        drop(server);
        drop(rpc_server);
        cleanup_test_storage(&root);
    }
}
