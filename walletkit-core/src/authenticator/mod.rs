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
/// Enable the `embed-zkeys` Cargo feature to activate these.
#[cfg(feature = "embed-zkeys")]
#[uniffi::export]
impl Groth16Materials {
    /// Loads Groth16 material from the embedded (compiled-in) zkeys and graphs.
    /// The material is baked into the binary at compile time, so no filesystem access is required.
    /// Requires the `embed-zkeys` Cargo feature.
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
/// Not available on WASM targets.
#[cfg(not(target_arch = "wasm32"))]
#[uniffi::export]
impl Groth16Materials {
    /// Loads Groth16 material from previously cached files on disk.
    /// Use `storage::cache_embedded_groth16_material` (requires `embed-zkeys`) to populate the cache.
    /// Not available on WASM targets.
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
    /// This is a 256-bit integer encoding the leaf index, recovery counter, and pubkey commitment.
    #[must_use]
    pub fn packed_account_data(&self) -> Uint256 {
        self.inner.packed_account_data.into()
    }

    /// Returns the Merkle tree leaf index for the holder's World ID.
    /// This value is private and should never be shared outside the authenticator.
    #[must_use]
    pub fn leaf_index(&self) -> u64 {
        self.inner.leaf_index()
    }

    /// Returns the on-chain secp256k1 address associated with this authenticator.
    /// This is the address used to identify the authenticator in the `WorldIDRegistry`.
    #[must_use]
    pub fn onchain_address(&self) -> String {
        self.inner.onchain_address().to_string()
    }

    /// Fetches the packed account data for the holder's World ID directly from the on-chain registry.
    /// Use this to get a fresh value when the locally cached `packed_account_data` may be stale.
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

    /// Generates a blinding factor for a credential `sub` by querying the OPRF nodes.
    /// `issuer_schema_id` identifies the issuer schema for which the blinding factor is derived.
    /// The returned value can be passed to `compute_credential_sub` to derive the credential `sub`.
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

    /// Signs an arbitrary challenge with the authenticator's on-chain secp256k1 key.
    /// **Dangerous**: the signature reveals the on-chain address, which can be used to derive `leaf_index`.
    /// Only use this when proving `leaf_index` to a trusted Recovery Agent.
    pub fn danger_sign_challenge(
        &self,
        challenge: &[u8],
    ) -> Result<Vec<u8>, WalletKitError> {
        let signature = self.inner.danger_sign_challenge(challenge)?;
        Ok(signature.as_bytes().to_vec())
    }

    /// Signs the EIP-712 `InitiateRecoveryAgentUpdate` payload and returns the raw signature bytes and signing nonce.
    /// Unlike `initiate_recovery_agent_update`, this does not submit anything to the gateway;
    /// callers can use the returned values to build and submit the request themselves.
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

    /// Submits a time-locked request to update the recovery agent; the change takes effect after a 14-day cooldown.
    /// `new_recovery_agent` is the checksummed hex Ethereum address of the new agent.
    /// Returns the gateway request ID, which can be polled with `poll_gateway_request_status`.
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

    /// Executes a previously initiated recovery agent update once the 14-day cooldown has elapsed.
    /// This call is permissionless — no signature is required; the contract enforces the cooldown.
    /// Returns the gateway request ID, which can be polled with `poll_gateway_request_status`.
    pub async fn execute_recovery_agent_update(
        &self,
    ) -> Result<String, WalletKitError> {
        let request_id = self.inner.execute_recovery_agent_update().await?;

        Ok(request_id.to_string())
    }

    /// Cancels a pending time-locked recovery agent update before the 14-day cooldown expires.
    /// Returns the gateway request ID, which can be polled with `poll_gateway_request_status`.
    pub async fn cancel_recovery_agent_update(&self) -> Result<String, WalletKitError> {
        let request_id = self.inner.cancel_recovery_agent_update().await?;

        Ok(request_id.to_string())
    }

    /// Inserts a new authenticator into this account, identified by its EdDSA `pubkey` and on-chain `address`.
    /// Poll the returned gateway request ID with `poll_gateway_request_status` to confirm finalization,
    /// then initialize the new authenticator using `init` or `init_with_defaults`.
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

    /// Replaces an existing authenticator slot (identified by `pubkey_id`) with a new key pair.
    /// `old_authenticator_address` identifies the slot to replace; the new slot is given by `new_authenticator_address` and `new_authenticator_pubkey`.
    /// Returns the gateway request ID, which can be polled with `poll_gateway_request_status`.
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

    /// Removes the authenticator at the given slot (identified by `authenticator_address` and `pubkey_id`) from this account.
    /// Returns the gateway request ID, which can be polled with `poll_gateway_request_status`.
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

    /// Polls the gateway for the current status of a previously submitted request.
    /// Works with request IDs returned by any of the authenticator-management or recovery methods.
    /// Returns a `GatewayRequestStatus` indicating whether the request is queued, submitted, finalized, or failed.
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
    /// Initializes a new `Authenticator` from a 32-byte seed using SDK-default config for the given environment.
    /// The World ID account must already be registered in the `WorldIDRegistry`; use `InitializingAuthenticator` to register first.
    /// `store` is used to cache credentials and inclusion proofs across sessions.
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

    /// Initializes a new `Authenticator` from a 32-byte seed and a JSON-encoded `AuthenticatorConfig`.
    /// The World ID account must already be registered in the `WorldIDRegistry`; use `InitializingAuthenticator` to register first.
    /// `store` is used to cache credentials and inclusion proofs across sessions.
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

    /// Generates a ZK proof for the given `ProofRequest`, using stored credentials and a fresh Merkle inclusion proof.
    /// `now` is the current Unix timestamp in seconds; on WASM it must be provided by the caller.
    /// Returns a `ProofResponse` containing the nullifier and per-credential proofs.
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

    /// Generates a WIP-103 ownership proof showing that the holder owns the credential `sub` without revealing `leaf_index`.
    /// `nonce` is an issuer-provided replay-prevention value; `blinding_factor` and `sub` must be consistent with this authenticator.
    /// Not supported on WASM targets.
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

/// Status for a registry gateway request.
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

/// An `Authenticator` in the process of being registered with the `WorldIDRegistry`.
/// Returned by `register` and `register_with_defaults`; call `poll_status` to track the gateway request.
/// Once the registration is finalized, initialize the full `Authenticator` using `init` or `init_with_defaults`.
#[derive(uniffi::Object)]
pub struct InitializingAuthenticator(CoreInitializingAuthenticator);

#[uniffi::export(async_runtime = "tokio")]
impl InitializingAuthenticator {
    /// Submits a new World ID registration using SDK-default config for the given environment.
    /// Returns immediately without waiting for finalization; call `poll_status` on the result to track progress.
    /// `recovery_address` is an optional checksummed hex Ethereum address to set as the initial recovery agent.
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

    /// Submits a new World ID registration using the provided JSON-encoded `AuthenticatorConfig`.
    /// Returns immediately without waiting for finalization; call `poll_status` on the result to track progress.
    /// `recovery_address` is an optional checksummed hex Ethereum address to set as the initial recovery agent.
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

    /// Polls the gateway for the status of this registration request.
    /// Returns a `GatewayRequestStatus` indicating whether the request is queued, submitted, finalized, or failed.
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

/// Signature and nonce returned by `danger_sign_initiate_recovery_agent_update`.
/// UniFFI does not support bare tuples across the FFI boundary, so the two values are bundled here.
#[derive(Debug, Clone, uniffi::Record)]
pub struct RecoveryUpdateSignature {
    /// Raw bytes of the secp256k1 ECDSA signature over the EIP-712 `InitiateRecoveryAgentUpdate` payload.
    pub signature: Vec<u8>,
    /// The EIP-712 signing nonce used when producing the signature; must be included in the gateway request.
    pub nonce: Uint256,
}

/// Identity material derived from a seed for use during account recovery.
/// All three values must be submitted on-chain as part of the recovery transaction
/// before the recovered account can be initialized with `Authenticator::init`.
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
    /// Derives the on-chain address, EdDSA public key, and off-chain signer commitment from a 32-byte seed.
    /// These values must be submitted on-chain as part of the recovery transaction.
    #[expect(clippy::missing_errors_doc, reason = "FFI")]
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

/// Derives recovery identity material from a 32-byte seed.
/// This is the FFI entry point for `RecoveryData::from_seed`; see that method for details.
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
