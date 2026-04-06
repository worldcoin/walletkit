//! The Authenticator is the main component with which users interact with the World ID Protocol.

use crate::{
    defaults::DefaultConfig, error::WalletKitError,
    primitives::ParseFromForeignBinding, Environment, FieldElement, Region,
};
use alloy_primitives::Address;
use ruint::aliases::U256;
use ruint_uniffi::Uint256;
use std::sync::Arc;
use world_id_core::{
    api_types::{GatewayErrorCode, GatewayRequestState},
    primitives::{authenticator::AuthenticatorPublicKeySet, Config},
    Authenticator as CoreAuthenticator, Credential as CoreCredential,
    InitializingAuthenticator as CoreInitializingAuthenticator,
    OnchainKeyRepresentable, Signer,
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
    #[tracing::instrument(
        target = "walletkit_latency",
        name = "rpc_account_data",
        skip_all
    )]
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
    #[tracing::instrument(
        target = "walletkit_latency",
        name = "oprf_blinding_factor",
        skip_all
    )]
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

    /// Signs the EIP-712 `InitiateRecoveryAgentUpdate` payload and returns the
    /// raw signature bytes and signing nonce without submitting anything to the
    /// gateway.
    ///
    /// This is the signing-only counterpart of [`Self::initiate_recovery_agent_update`].
    /// Callers can use the returned bytes to build and submit the gateway request
    /// themselves.
    ///
    /// # Warning
    /// This method uses the `onchain_signer` (secp256k1 ECDSA) and produces a
    /// recoverable signature. Any holder of the signature together with the
    /// EIP-712 parameters can call `ecrecover` to obtain the `onchain_address`,
    /// which can then be looked up in the registry to derive the user's
    /// `leaf_index`. Only expose the output to trusted parties (e.g. a Recovery
    /// Agent).
    ///
    /// # Arguments
    /// * `new_recovery_agent` — the checksummed hex address of the new recovery
    ///   agent (e.g. `"0x1234…"`).
    ///
    /// # Errors
    /// - Returns [`WalletKitError::InvalidInput`] if `new_recovery_agent` is not
    ///   a valid address.
    /// - Returns an error if the nonce fetch or signing step fails.
    pub async fn danger_sign_initiate_recovery_agent_update(
        &self,
        new_recovery_agent: String,
    ) -> Result<RecoveryUpdateSignature, WalletKitError> {
        let new_recovery_agent =
            Address::parse_from_ffi(&new_recovery_agent, "new_recovery_agent")?;
        let (sig, nonce) = self
            .inner
            .danger_sign_initiate_recovery_agent_update(new_recovery_agent)
            .await?;
        Ok(RecoveryUpdateSignature {
            signature: sig.as_bytes().to_vec(),
            nonce: nonce.into(),
        })
    }

    /// Initiates a time-locked recovery agent update (14-day cooldown).
    ///
    /// Signs an EIP-712 `InitiateRecoveryAgentUpdate` payload and submits it to
    /// the gateway. Returns the gateway request ID that can be used to poll
    /// status.
    ///
    /// # Arguments
    /// * `new_recovery_agent` — the checksummed hex address of the new recovery
    ///   agent (e.g. `"0x1234…"`).
    ///
    /// # Errors
    /// - Returns [`WalletKitError::InvalidInput`] if `new_recovery_agent` is not
    ///   a valid address.
    /// - Returns a network error if the gateway request fails.
    pub async fn initiate_recovery_agent_update(
        &self,
        new_recovery_agent: String,
    ) -> Result<String, WalletKitError> {
        let new_recovery_agent =
            Address::parse_from_ffi(&new_recovery_agent, "new_recovery_agent")?;

        let request_id = self
            .inner
            .initiate_recovery_agent_update(new_recovery_agent)
            .await?;

        Ok(request_id.to_string())
    }

    /// Executes a pending recovery agent update after the 14-day cooldown has
    /// elapsed.
    ///
    /// This call is **permissionless** — no signature is required. The contract
    /// enforces the cooldown and will revert with
    /// `RecoveryAgentUpdateStillInCooldown` if called too early.
    ///
    /// Returns the gateway request ID that can be used to poll status.
    ///
    /// # Errors
    /// Returns a network error if the gateway request fails.
    pub async fn execute_recovery_agent_update(
        &self,
    ) -> Result<String, WalletKitError> {
        let request_id = self.inner.execute_recovery_agent_update().await?;

        Ok(request_id.to_string())
    }

    /// Cancels a pending time-locked recovery agent update before the cooldown
    /// expires.
    ///
    /// Signs an EIP-712 `CancelRecoveryAgentUpdate` payload and submits it to
    /// the gateway. Returns the gateway request ID that can be used to poll
    /// status.
    ///
    /// # Errors
    /// Returns a network error if the gateway request fails.
    pub async fn cancel_recovery_agent_update(&self) -> Result<String, WalletKitError> {
        let request_id = self.inner.cancel_recovery_agent_update().await?;

        Ok(request_id.to_string())
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
    #[tracing::instrument(target = "walletkit_latency", name = "rpc_init", skip_all)]
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
    #[tracing::instrument(target = "walletkit_latency", name = "rpc_init", skip_all)]
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

        // TODO: If request is to initiate a session, call `self.inner.generate_session_id` and cache seed

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

        let account_inclusion_proof =
            self.fetch_inclusion_proof_with_cache(now).await?;

        // Next, generate the nullifier and check the replay guard
        let nullifier = self
            .inner
            .generate_nullifier(&proof_request.0, Some(account_inclusion_proof.clone()))
            .await?;

        if self
            .store
            .is_nullifier_replay(nullifier.verifiable_oprf_output.output.into(), now)?
        {
            return Err(WalletKitError::NullifierReplay);
        }

        // If the request is for a Session Proof, get the correct `session_id_r_seed`, either
        // from the cache or compute it again
        let session_id_r_seed = if let Some(session_id) = proof_request.0.session_id {
            let cached_r_seed =
                self.store.get_session_seed(session_id.oprf_seed, now)?;

            if cached_r_seed.is_some() {
                cached_r_seed
            } else {
                let (expected_session_id, seed) = self
                    .inner
                    .generate_session_id(
                        &proof_request.0,
                        None,
                        Some(account_inclusion_proof),
                    )
                    .await?;

                if expected_session_id != session_id {
                    return Err(WalletKitError::SessionIdMismatch);
                }

                if let Err(err) =
                    self.store
                        .store_session_seed(session_id.oprf_seed, seed, now)
                {
                    tracing::error!("error caching session_id_r_seed: {}", err);
                }

                Some(seed)
            }
        } else {
            None
        };

        let mut responses: Vec<ResponseItem> = vec![];

        for request_item in credentials_to_prove {
            let (credential, blinding_factor) = self
                .store
                .get_credential(request_item.issuer_schema_id, now)?
                .ok_or(WalletKitError::CredentialNotIssued)?;

            let response_item = self.inner.generate_single_proof(
                nullifier.clone(),
                request_item,
                &credential,
                blinding_factor.0,
                session_id_r_seed.unwrap_or(CoreFieldElement::ZERO), // TODO: upstream update coming accepting Option
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
            session_id: proof_request.0.session_id,
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
    #[tracing::instrument(
        target = "walletkit_latency",
        name = "gateway_register",
        skip_all
    )]
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
    #[tracing::instrument(
        target = "walletkit_latency",
        name = "gateway_register",
        skip_all
    )]
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
    #[tracing::instrument(
        target = "walletkit_latency",
        name = "gateway_poll",
        skip_all
    )]
    pub async fn poll_status(&self) -> Result<RegistrationStatus, WalletKitError> {
        let status = self.0.poll_status().await?;
        Ok(status.into())
    }
}

/// The signature and signing nonce returned by
/// [`Authenticator::danger_sign_initiate_recovery_agent_update`].
///
/// `UniFFI` does not support returning bare tuples across the FFI boundary, so
/// the two values are bundled in this record type.
#[derive(Debug, Clone, uniffi::Record)]
pub struct RecoveryUpdateSignature {
    /// Raw bytes of the secp256k1 ECDSA signature over the EIP-712
    /// `InitiateRecoveryAgentUpdate` payload.
    pub signature: Vec<u8>,
    /// The EIP-712 signing nonce that was used; must be included in the
    /// gateway request alongside the signature.
    pub nonce: Uint256,
}

/// Identity material derived from a seed for use during account recovery.
///
/// During account recovery the user generates new keys from a seed, but those
/// keys do not yet exist on-chain. The three values in this record must be
/// submitted on-chain during the recovery transaction.
///
/// All fields are hex-encoded strings suitable for direct use in API requests.
#[derive(Debug, Clone, uniffi::Record)]
pub struct RecoveryData {
    /// Checksummed hex Ethereum address of the on-chain signer.
    pub authenticator_address: String,
    /// Hex-encoded U256 compressed `EdDSA` public key of the off-chain signer.
    pub authenticator_pubkey: String,
    /// Hex-encoded U256 Poseidon2 hash commitment over the authenticator key set.
    pub offchain_signer_commitment: String,
}

impl RecoveryData {
    /// Derives recovery identity material from a 32-byte seed.
    ///
    /// These values must be submitted on-chain as part of the recovery
    /// transaction before the recovered account can be initialised with
    /// [`Authenticator::init`] / [`Authenticator::init_with_defaults`].
    ///
    /// # Errors
    /// Returns [`WalletKitError`] if the seed is invalid or serialization fails.
    pub fn from_seed(seed: &[u8]) -> Result<Self, WalletKitError> {
        let signer = Signer::from_seed_bytes(seed)?;
        let authenticator_address = signer.onchain_signer_address().to_checksum(None);
        let authenticator_pubkey: U256 = signer
            .offchain_signer_pubkey()
            .to_ethereum_representation()?;
        let mut key_set = AuthenticatorPublicKeySet::default();
        key_set.try_push(signer.offchain_signer_pubkey())?;
        let offchain_signer_commitment: U256 = key_set.leaf_hash().into();

        Ok(Self {
            authenticator_address,
            authenticator_pubkey: format!("{authenticator_pubkey:#066x}"),
            offchain_signer_commitment: format!("{offchain_signer_commitment:#066x}"),
        })
    }
}

/// Derives recovery data from a 32-byte seed.
///
/// This is the foreign-bindings entrypoint for recovery data generation.
///
/// # Errors
/// Returns [`WalletKitError`] if the seed is invalid or serialization fails.
#[uniffi::export]
pub fn recovery_data_from_seed(seed: &[u8]) -> Result<RecoveryData, WalletKitError> {
    RecoveryData::from_seed(seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recovery_data_from_seed() {
        let seed = [1u8; 32];
        let material = RecoveryData::from_seed(&seed).expect("should derive material");

        // `authenticator_address` must be a checksummed 0x-prefixed hex address.
        assert!(
            material.authenticator_address.starts_with("0x"),
            "address should start with 0x"
        );
        assert_eq!(
            material.authenticator_address.len(),
            42,
            "address should be 42 chars (0x + 40 hex digits)"
        );

        // `authenticator_pubkey` must be a 0x-prefixed, zero-padded 64-hex-digit U256.
        assert!(
            material.authenticator_pubkey.starts_with("0x"),
            "pubkey should start with 0x"
        );
        assert!(
            material.authenticator_pubkey.len() <= 66,
            "pubkey should be at most 66 chars (0x + 64 hex digits)"
        );

        // `offchain_signer_commitment` must be a 0x-prefixed, zero-padded 64-hex-digit U256.
        assert!(
            material.offchain_signer_commitment.starts_with("0x"),
            "commitment should start with 0x"
        );
        assert!(
            material.offchain_signer_commitment.len() <= 66,
            "commitment should be at most 66 chars (0x + 64 hex digits)"
        );

        // All fields must be non-empty beyond the prefix.
        assert!(
            material.authenticator_address.len() > 2,
            "address should be non-empty"
        );
        assert!(
            material.authenticator_pubkey.len() > 2,
            "pubkey should be non-empty"
        );
        assert!(
            material.offchain_signer_commitment.len() > 2,
            "commitment should be non-empty"
        );
    }

    #[test]
    fn test_recovery_data_rejects_invalid_seed() {
        // Seed must be exactly 32 bytes.
        let result = RecoveryData::from_seed(&[0u8; 16]);
        assert!(result.is_err(), "should reject 16-byte seed");

        let result = RecoveryData::from_seed(&[]);
        assert!(result.is_err(), "should reject empty seed");
    }
}

#[cfg(all(test, feature = "storage"))]
mod storage_tests {
    use super::*;
    use crate::storage::cache_embedded_groth16_material;
    use crate::storage::tests_utils::{
        cleanup_test_storage, temp_root_path, InMemoryStorageProvider,
    };
    use alloy::primitives::address;

    async fn init_test_authenticator(
        seed: &[u8],
    ) -> (Authenticator, std::path::PathBuf) {
        let mut mock_server = mockito::Server::new_async().await;

        // Mock eth_call to return account data indicating account exists.
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
        let authenticator = Authenticator::init(seed, &config, &paths, Arc::new(store))
            .await
            .unwrap();
        drop(mock_server);

        (authenticator, root)
    }

    #[tokio::test]
    async fn test_init_with_config_and_storage() {
        // Install default crypto provider for rustls.
        let _ = rustls::crypto::ring::default_provider().install_default();

        let (_, root) = init_test_authenticator(&[2u8; 32]).await;
        cleanup_test_storage(&root);
    }
}
