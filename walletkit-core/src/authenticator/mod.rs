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
    api_types::{GatewayErrorCode, GatewayRequestId, GatewayRequestState},
    primitives::{AuthenticatorPublicKeySet, Config},
    Authenticator as CoreAuthenticator, AuthenticatorConfig,
    Credential as CoreCredential, CredentialInput, EdDSAPublicKey,
    InitializingAuthenticator as CoreInitializingAuthenticator,
    OnchainKeyRepresentable, Signer,
};

use crate::requests::{ProofRequest, ProofResponse};
use crate::storage::CredentialStore;
#[cfg(not(target_arch = "wasm32"))]
use crate::storage::StoragePaths;
use crate::OwnershipProof;

mod with_storage;

/// ZK Proof material for both Groth16 proofs (query & nullifier proofs)
#[derive(Clone, uniffi::Object)]
pub struct Groth16Materials {
    query: Arc<world_id_core::proof::CircomGroth16Material>,
    nullifier: Arc<world_id_core::proof::CircomGroth16Material>,
}

impl std::fmt::Debug for Groth16Materials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Groth16Materials").finish_non_exhaustive()
    }
}

/// Constructors that require embedded zkeys compiled into the binary.
///
/// Enable the `embed-zkeys` Cargo feature to activate these.
#[cfg(feature = "embed-zkeys")]
#[uniffi::export]
impl Groth16Materials {
    /// Loads Groth16 material from the embedded (compiled-in) zkeys and graphs.
    ///
    /// Requires the `embed-zkeys` feature. The material is baked into the binary at
    /// compile time so no filesystem access is required, and this works on every
    /// platform including WASM.
    ///
    /// # Errors
    ///
    /// Returns an error if the embedded material cannot be loaded or verified.
    #[uniffi::constructor]
    pub fn from_embedded() -> Result<Self, WalletKitError> {
        let query =
            world_id_core::proof::load_embedded_query_material().map_err(|error| {
                WalletKitError::Groth16MaterialEmbeddedLoad {
                    error: error.to_string(),
                }
            })?;
        let nullifier = world_id_core::proof::load_embedded_nullifier_material()
            .map_err(|error| WalletKitError::Groth16MaterialEmbeddedLoad {
                error: error.to_string(),
            })?;
        Ok(Self {
            query: Arc::new(query),
            nullifier: Arc::new(nullifier),
        })
    }
}

/// Constructors that load Groth16 material from the native filesystem.
///
/// Not available on WASM targets (no filesystem access).
#[cfg(not(target_arch = "wasm32"))]
#[uniffi::export]
impl Groth16Materials {
    /// Loads Groth16 material from cached files on disk.
    ///
    /// Use `storage::cache_embedded_groth16_material` (requires the `embed-zkeys` feature)
    /// to populate the cache before calling this.
    ///
    /// Not available on WASM (no filesystem).
    ///
    /// # Errors
    ///
    /// Returns an error if the cached files cannot be read or verified.
    #[uniffi::constructor]
    // `Arc<StoragePaths>` must be taken by value: UniFFI constructors receive
    // object arguments as owned `Arc`s across the FFI boundary, so passing by
    // reference is not an option here.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "UniFFI constructors require owned Arc arguments"
    )]
    pub fn from_cache(paths: Arc<StoragePaths>) -> Result<Self, WalletKitError> {
        let query_zkey = paths.query_zkey_path();
        let nullifier_zkey = paths.nullifier_zkey_path();
        let query_graph = paths.query_graph_path();
        let nullifier_graph = paths.nullifier_graph_path();

        let query = world_id_core::proof::load_query_material_from_paths(
            &query_zkey,
            &query_graph,
        )
        .map_err(|error| WalletKitError::Groth16MaterialCacheInvalid {
            path: format!(
                "{} and {}",
                query_zkey.to_string_lossy(),
                query_graph.to_string_lossy()
            ),
            error: error.to_string(),
        })?;

        let nullifier = world_id_core::proof::load_nullifier_material_from_paths(
            &nullifier_zkey,
            &nullifier_graph,
        )
        .map_err(|error| WalletKitError::Groth16MaterialCacheInvalid {
            path: format!(
                "{} and {}",
                nullifier_zkey.to_string_lossy(),
                nullifier_graph.to_string_lossy()
            ),
            error: error.to_string(),
        })?;

        Ok(Self {
            query: Arc::new(query),
            nullifier: Arc::new(nullifier),
        })
    }
}

/// The Authenticator is the main component with which users interact with the World ID Protocol.
#[derive(Debug, uniffi::Object)]
pub struct Authenticator {
    inner: CoreAuthenticator,
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
        let packed_account_data = self.inner.fetch_packed_account_data().await?;
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

    /// Inserts a new authenticator into this account.
    ///
    /// Accepts the new authenticator's compressed EdDSA public key as a U256 and its on-chain signer
    /// address as a hex string. Returns a gateway request ID; poll it with `poll_gateway_request_status`
    /// to wait for finalization before initializing the new authenticator.
    #[expect(clippy::missing_errors_doc, reason = "FFI")]
    pub async fn insert_authenticator(
        &self,
        new_authenticator_pubkey: Uint256,
        new_authenticator_address: String,
    ) -> Result<String, WalletKitError> {
        let new_authenticator_pubkey = eddsa_public_key_from_uint256(
            new_authenticator_pubkey,
            "new_authenticator_pubkey",
        )?;
        let new_authenticator_address = Address::parse_from_ffi(
            &new_authenticator_address,
            "new_authenticator_address",
        )?;

        let request_id = self
            .inner
            .insert_authenticator(new_authenticator_pubkey, new_authenticator_address)
            .await?;

        Ok(request_id.to_string())
    }

    /// Updates an existing authenticator slot.
    ///
    /// `pubkey_id` identifies the slot to replace; supply the old signer address, the new signer address,
    /// and the new compressed EdDSA public key as a U256. Returns a gateway request ID; poll it with
    /// `poll_gateway_request_status` to wait for finalization.
    #[expect(clippy::missing_errors_doc, reason = "FFI")]
    pub async fn update_authenticator(
        &self,
        old_authenticator_address: String,
        new_authenticator_address: String,
        new_authenticator_pubkey: Uint256,
        pubkey_id: u32,
    ) -> Result<String, WalletKitError> {
        let old_authenticator_address = Address::parse_from_ffi(
            &old_authenticator_address,
            "old_authenticator_address",
        )?;
        let new_authenticator_address = Address::parse_from_ffi(
            &new_authenticator_address,
            "new_authenticator_address",
        )?;
        let new_authenticator_pubkey = eddsa_public_key_from_uint256(
            new_authenticator_pubkey,
            "new_authenticator_pubkey",
        )?;

        let request_id = self
            .inner
            .update_authenticator(
                old_authenticator_address,
                new_authenticator_address,
                new_authenticator_pubkey,
                pubkey_id,
            )
            .await?;

        Ok(request_id.to_string())
    }

    /// Removes an authenticator from this account.
    ///
    /// `authenticator_address` and `pubkey_id` together identify the slot to remove. Returns a gateway
    /// request ID; poll it with `poll_gateway_request_status` to wait for finalization.
    #[expect(clippy::missing_errors_doc, reason = "FFI")]
    pub async fn remove_authenticator(
        &self,
        authenticator_address: String,
        pubkey_id: u32,
    ) -> Result<String, WalletKitError> {
        let authenticator_address =
            Address::parse_from_ffi(&authenticator_address, "authenticator_address")?;

        let request_id = self
            .inner
            .remove_authenticator(authenticator_address, pubkey_id)
            .await?;

        Ok(request_id.to_string())
    }

    /// Polls the gateway for the status of a previously submitted request.
    ///
    /// Accepts a request ID returned by any authenticator-management or recovery method. Returns a
    /// `GatewayRequestStatus` indicating whether the request is queued, submitted, finalized, or failed.
    #[expect(clippy::missing_errors_doc, reason = "FFI")]
    pub async fn poll_gateway_request_status(
        &self,
        request_id: String,
    ) -> Result<GatewayRequestStatus, WalletKitError> {
        let request_id = gateway_request_id_from_string(&request_id);
        let status = self.inner.poll_status(&request_id).await?;
        Ok(status.into())
    }
}

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
        materials: Arc<Groth16Materials>,
        store: Arc<CredentialStore>,
    ) -> Result<Self, WalletKitError> {
        let config = Config::from_environment(environment, rpc_url, region)?;
        let authenticator = CoreAuthenticator::init(seed, config.into())
            .await?
            .with_proof_materials(
                Arc::clone(&materials.query),
                Arc::clone(&materials.nullifier),
            );
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
        materials: Arc<Groth16Materials>,
        store: Arc<CredentialStore>,
    ) -> Result<Self, WalletKitError> {
        let config = AuthenticatorConfig::from_json(config).map_err(|_| {
            WalletKitError::InvalidInput {
                attribute: "config".to_string(),
                reason: "Invalid config".to_string(),
            }
        })?;
        let authenticator = CoreAuthenticator::init(seed, config)
            .await?
            .with_proof_materials(
                Arc::clone(&materials.query),
                Arc::clone(&materials.nullifier),
            );
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
            #[cfg(target_arch = "wasm32")]
            {
                return Err(WalletKitError::InvalidInput {
                    attribute: "now".to_string(),
                    reason: "`now` must be provided on wasm32 targets".to_string(),
                });
            }

            #[cfg(not(target_arch = "wasm32"))]
            {
                let start = std::time::SystemTime::now();
                start
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|e| WalletKitError::Generic {
                        error: format!("Critical. Unable to determine SystemTime: {e}"),
                    })?
                    .as_secs()
            }
        };

        // Build CredentialInput list from storage
        // Note: We simply load all non-expired credentials. Filtering for the requested schema IDs is done in `generate_proof`.
        // We could avoid unnecessary loading by filtering via `world_id_primitives::ProofRequest::credentials_to_prove`. We consider this an
        // unnecessary optimization for now.
        let credentials: Vec<_> = self
            .store
            .list_credentials(None, now)?
            .iter()
            .filter(|c| !c.is_expired)
            .filter_map(|cred| {
                if let Ok(Some((credential, blinding_factor))) =
                    self.store.get_credential(cred.issuer_schema_id, now)
                {
                    Some(CredentialInput {
                        credential: credential.into(),
                        blinding_factor: blinding_factor.into(),
                    })
                } else {
                    tracing::warn!(
                        issuer_schema_id = %cred.issuer_schema_id,
                        credential_id = %cred.credential_id,
                        "credential listed but not loadable, skipping"
                    );
                    None
                }
            })
            .collect();

        let account_inclusion_proof =
            self.fetch_inclusion_proof_with_cache(now).await?;

        // Generate the nullifier and check the replay guard
        // Box::pin to heap-allocate the large upstream futures and keep this future below clippy::large_futures threshold
        let nullifier = Box::pin(self.inner.generate_nullifier(
            &proof_request.0,
            Some(account_inclusion_proof.clone()),
        ))
        .await?;

        if self
            .store
            .is_nullifier_replay(nullifier.verifiable_oprf_output.output.into(), now)?
        {
            return Err(WalletKitError::NullifierReplay);
        }

        // Get cached `session_id_r_seed` if session ID is provided in the proof request
        let session_id_r_seed =
            proof_request
                .0
                .session_id
                .and_then(|session_id| {
                    match self.store.get_session_seed(session_id.oprf_seed, now) {
                        Ok(seed) => seed,
                        Err(err) => {
                            tracing::warn!(error = %err, "failed to load cached session seed, continuing without");
                            None
                        }
                    }
                });

        // Handles credential selection, session resolution, per-credential proofs, response assembly, and validation
        let result = Box::pin(self.inner.generate_proof(
            &proof_request.0,
            nullifier.clone(),
            &credentials,
            Some(account_inclusion_proof),
            session_id_r_seed,
        ))
        .await?;

        // Cache session seed if returned
        if let Some(seed) = result.session_id_r_seed {
            if let Some(session_id) = proof_request.0.session_id {
                if let Err(err) =
                    self.store
                        .store_session_seed(session_id.oprf_seed, seed, now)
                {
                    tracing::error!("error caching session_id_r_seed: {}", err);
                }
            }
        }

        self.store
            .replay_guard_set(nullifier.verifiable_oprf_output.output.into(), now)?;

        Ok(result.proof_response.into())
    }

    /// Generates a WIP-103 Ownership Proof for Issuers.
    ///
    /// An Ownership Proof lets the user prove they own the credential `sub`
    /// associated with a stored credential without revealing their `leaf_index`.
    ///
    /// # Security-critical usage constraint
    /// This method **MUST only** be called as part of a direct
    /// **user-initiated** action in the client. Callers **MUST NOT** expose this
    /// method to issuer-triggered, backend-triggered, or unauthenticated request
    /// flows.
    ///
    /// # Arguments
    /// * `nonce` - A field element provided by the Issuer to prevent replay.
    /// * `blinding_factor` - The credential blinding factor previously used to
    ///   derive the credential `sub`.
    /// * `sub` - The credential `sub` (commitment) to prove ownership of.
    ///
    /// # Errors
    /// - Returns [`WalletKitError::InvalidInput`] if `blinding_factor` and
    ///   `sub` are inconsistent with each other (i.e. `sub` was not derived
    ///   from this authenticator's leaf index and the provided blinding factor).
    /// - Returns a network error if the Merkle inclusion proof cannot be
    ///   fetched from the indexer.
    /// - Returns [`WalletKitError::ProofGeneration`] if the ZK proof fails.
    pub async fn prove_credential_sub(
        &self,
        nonce: &FieldElement,
        blinding_factor: &FieldElement,
        sub: &FieldElement,
    ) -> Result<OwnershipProof, WalletKitError> {
        #[cfg(target_arch = "wasm32")]
        {
            let _ = (nonce, blinding_factor, sub);
            return Err(WalletKitError::Generic {
                error: "credential ownership proofs are not supported on wasm32"
                    .to_string(),
            });
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| WalletKitError::Generic {
                    error: format!("Critical. Unable to determine SystemTime: {e}"),
                })?
                .as_secs();

            let inclusion_proof = self.fetch_inclusion_proof_with_cache(now).await?;
            let proof = self
                .inner
                .prove_credential_sub(
                    nonce.0,
                    blinding_factor.0,
                    sub.0,
                    Some(inclusion_proof),
                )
                .await?;

            Ok(OwnershipProof(proof))
        }
    }
}

/// Registration status for a World ID being created through the gateway.
#[derive(Debug, Clone, uniffi::Enum)]
pub enum GatewayRequestStatus {
    /// Request queued but not yet batched.
    Queued,
    /// Request currently being batched.
    Batching,
    /// Request submitted on-chain.
    Submitted {
        /// Transaction hash emitted when the request was submitted.
        tx_hash: String,
    },
    /// Request finalized on-chain.
    Finalized {
        /// Transaction hash emitted when the request was finalized.
        tx_hash: String,
    },
    /// Request failed during processing.
    Failed {
        /// Error message returned by the gateway.
        error: String,
        /// Specific error code, if available.
        error_code: Option<String>,
    },
}

impl From<GatewayRequestState> for GatewayRequestStatus {
    fn from(state: GatewayRequestState) -> Self {
        match state {
            GatewayRequestState::Queued => Self::Queued,
            GatewayRequestState::Batching => Self::Batching,
            GatewayRequestState::Submitted { tx_hash } => Self::Submitted { tx_hash },
            GatewayRequestState::Finalized { tx_hash } => Self::Finalized { tx_hash },
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
    #[expect(clippy::missing_errors_doc, reason = "FFI")]
    pub async fn register_with_defaults(
        seed: &[u8],
        rpc_url: Option<String>,
        environment: &Environment,
        region: Option<Region>,
        recovery_address: Option<String>,
    ) -> Result<Self, WalletKitError> {
        let recovery_address =
            Address::parse_from_ffi_optional(recovery_address, "recovery_address")?;

        let config =
            AuthenticatorConfig::from_environment(environment, rpc_url, region)?;

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
    #[expect(clippy::missing_errors_doc, reason = "FFI")]
    pub async fn register(
        seed: &[u8],
        config: &str,
        recovery_address: Option<String>,
    ) -> Result<Self, WalletKitError> {
        let recovery_address =
            Address::parse_from_ffi_optional(recovery_address, "recovery_address")?;

        let config = AuthenticatorConfig::from_json(config).map_err(|_| {
            WalletKitError::InvalidInput {
                attribute: "config".to_string(),
                reason: "Invalid config".to_string(),
            }
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
    #[expect(clippy::missing_errors_doc, reason = "FFI")]
    pub async fn poll_status(&self) -> Result<GatewayRequestStatus, WalletKitError> {
        let status = self.0.poll_status().await?;
        Ok(status.into())
    }
}

fn eddsa_public_key_from_uint256(
    public_key: Uint256,
    attribute: &'static str,
) -> Result<EdDSAPublicKey, WalletKitError> {
    let public_key: U256 = public_key.into();
    EdDSAPublicKey::from_compressed_bytes(public_key.to_le_bytes()).map_err(|error| {
        WalletKitError::InvalidInput {
            attribute: attribute.to_string(),
            reason: error.to_string(),
        }
    })
}

fn gateway_request_id_from_string(request_id: &str) -> GatewayRequestId {
    GatewayRequestId::new(request_id.strip_prefix("gw_").unwrap_or(request_id))
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
    #[cfg(feature = "embed-zkeys")]
    use crate::storage::tests_utils::{
        cleanup_test_storage, temp_root_path, InMemoryStorageProvider,
    };
    #[cfg(feature = "embed-zkeys")]
    use alloy::primitives::address;
    #[cfg(feature = "embed-zkeys")]
    use world_id_core::primitives::Config;

    #[test]
    fn test_recovery_data_from_seed() {
        let seed = [1u8; 32];
        let material = RecoveryData::from_seed(&seed).expect("should derive material");

        assert!(material.authenticator_address.starts_with("0x"));
        assert_eq!(material.authenticator_address.len(), 42);
        assert!(material.authenticator_pubkey.starts_with("0x"));
        assert!(material.authenticator_pubkey.len() <= 66);
        assert!(material.offchain_signer_commitment.starts_with("0x"));
        assert!(material.offchain_signer_commitment.len() <= 66);
        assert!(material.authenticator_address.len() > 2);
        assert!(material.authenticator_pubkey.len() > 2);
        assert!(material.offchain_signer_commitment.len() > 2);
    }

    #[test]
    fn test_recovery_data_rejects_invalid_seed() {
        assert!(RecoveryData::from_seed(&[0u8; 16]).is_err());
        assert!(RecoveryData::from_seed(&[]).is_err());
    }

    #[test]
    fn parses_recovery_data_pubkey_for_authenticator_management() {
        let seed = [7u8; 32];
        let signer = Signer::from_seed_bytes(&seed).expect("valid seed");
        let material = RecoveryData::from_seed(&seed).expect("recovery data");
        let encoded_pubkey = Uint256::try_from(
            material
                .authenticator_pubkey
                .strip_prefix("0x")
                .unwrap_or(&material.authenticator_pubkey)
                .to_string(),
        )
        .expect("valid uint");

        let parsed_pubkey =
            eddsa_public_key_from_uint256(encoded_pubkey, "new_authenticator_pubkey")
                .expect("valid compressed EdDSA pubkey");

        assert_eq!(
            parsed_pubkey.to_ethereum_representation().unwrap(),
            signer
                .offchain_signer_pubkey()
                .to_ethereum_representation()
                .unwrap()
        );
    }

    #[test]
    fn rejects_invalid_management_pubkey() {
        let error = eddsa_public_key_from_uint256(
            Uint256::from(U256::ZERO),
            "new_authenticator_pubkey",
        )
        .expect_err("zero is not a valid compressed EdDSA pubkey");

        assert!(matches!(
            error,
            WalletKitError::InvalidInput {
                ref attribute,
                ..
            } if attribute == "new_authenticator_pubkey"
        ));
    }

    #[test]
    fn gateway_request_status_preserves_transaction_hashes() {
        let submitted = GatewayRequestStatus::from(GatewayRequestState::Submitted {
            tx_hash: "0xabc".to_string(),
        });
        assert!(matches!(
            submitted,
            GatewayRequestStatus::Submitted { ref tx_hash } if tx_hash == "0xabc"
        ));

        let finalized = GatewayRequestStatus::from(GatewayRequestState::Finalized {
            tx_hash: "0xdef".to_string(),
        });
        assert!(matches!(
            finalized,
            GatewayRequestStatus::Finalized { ref tx_hash } if tx_hash == "0xdef"
        ));
    }

    #[test]
    fn gateway_request_id_from_string_accepts_prefixed_and_unprefixed_ids() {
        assert_eq!(
            gateway_request_id_from_string("gw_insert-001").to_string(),
            "gw_insert-001"
        );
        assert_eq!(
            gateway_request_id_from_string("insert-001").to_string(),
            "gw_insert-001"
        );
    }

    #[cfg(feature = "embed-zkeys")]
    #[tokio::test]
    async fn test_init_with_config_and_materials() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let mut mock_server = mockito::Server::new_async().await;
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
            "https://indexer.us.id-infra.worldcoin.dev".to_string(),
            "https://gateway.id-infra.worldcoin.dev".to_string(),
            vec![],
            2,
        )
        .unwrap();
        let config = serde_json::to_string(&config).unwrap();

        let root = temp_root_path();
        let provider = InMemoryStorageProvider::new(&root);
        let store = CredentialStore::from_provider(&provider).expect("store");
        store.init(42, 100).expect("init storage");

        let materials =
            Arc::new(Groth16Materials::from_embedded().expect("load materials"));
        let _authenticator =
            Authenticator::init(&[2u8; 32], &config, materials, Arc::new(store))
                .await
                .unwrap();
        drop(mock_server);

        cleanup_test_storage(&root);
    }
}
