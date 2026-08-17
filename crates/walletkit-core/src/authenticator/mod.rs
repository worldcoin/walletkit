//! The Authenticator is the main component with which users interact with the World ID Protocol.

use crate::{
    authenticator::artifacts::WalletKitZkArtifactSource, defaults,
    error::WalletKitError, primitives::ParseFromForeignBinding, Environment,
    FieldElement, Region,
};
use alloy_core::primitives::Address;
use ruint::aliases::U256;
use ruint_uniffi::Uint256;
use std::sync::Arc;
use world_id_core::{
    api_types::{GatewayErrorCode, GatewayRequestId, GatewayRequestState},
    primitives::{AuthenticatorPublicKeySet, Config, MAX_AUTHENTICATOR_KEYS},
    Authenticator as CoreAuthenticator, AuthenticatorError,
    Credential as CoreCredential, CredentialInput, EdDSAPublicKey,
    InitializingAuthenticator as CoreInitializingAuthenticator,
    OnchainKeyRepresentable, Signer,
};

use crate::requests::{ProofRequest, ProofResponse};
use crate::storage::CredentialStore;
use crate::OwnershipProof;

pub mod artifacts;
mod with_storage;

/// The Authenticator is the main component with which users interact with the World ID Protocol.
#[derive(Debug, uniffi::Object)]
pub struct Authenticator {
    inner: CoreAuthenticator,
    store: Arc<CredentialStore>,
}

impl Authenticator {
    /// Initializes a new Authenticator from a seed and an already-parsed
    /// [`Config`].
    ///
    /// # Errors
    /// See `CoreAuthenticator::init` for potential errors.
    pub async fn init_with_config(
        seed: &[u8],
        config: Config,
        artifacts: Arc<dyn WalletKitZkArtifactSource>,
        store: Arc<CredentialStore>,
    ) -> Result<Self, WalletKitError> {
        let authenticator = CoreAuthenticator::init(seed, config, artifacts).await?;

        Ok(Self {
            inner: authenticator,
            store,
        })
    }
}

fn parse_authenticator_pubkey(
    attribute: &str,
    encoded_pubkey: impl AsRef<str>,
) -> Result<EdDSAPublicKey, WalletKitError> {
    let encoded_pubkey = encoded_pubkey.as_ref();
    let invalid_input = |reason: String| WalletKitError::InvalidInput {
        attribute: attribute.to_string(),
        reason,
    };
    let hex = encoded_pubkey.strip_prefix("0x").ok_or_else(|| {
        invalid_input("Public key must start with a 0x prefix".to_string())
    })?;

    if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid_input(
            "Public key must be exactly 32 bytes (64 hex characters) after the 0x prefix"
                .to_string(),
        ));
    }

    let encoded = U256::from_str_radix(hex, 16)
        .map_err(|error| invalid_input(error.to_string()))?;
    let pubkey = EdDSAPublicKey::from_compressed_bytes(encoded.to_le_bytes())
        .map_err(|error| invalid_input(error.to_string()))?;

    // `from_compressed_bytes` accepts the curve's neutral element and a
    // sign-bit alias of it. Empty key-set slots hash as the neutral element
    // on-chain (a slot holding it is commitment-indistinguishable from an
    // empty slot, and it is unusable for verification), so reject it and any
    // encoding that does not round-trip to the canonical form.
    let canonical = pubkey
        .to_ethereum_representation()
        .map_err(|error| invalid_input(error.to_string()))?;
    if canonical != encoded {
        return Err(invalid_input(
            "Public key is not the canonical compressed point encoding".to_string(),
        ));
    }
    if canonical == U256::from(1u64) {
        return Err(invalid_input(
            "Public key must not be the BabyJubJub identity point".to_string(),
        ));
    }

    Ok(pubkey)
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
    #[allow(
        clippy::needless_pass_by_value,
        reason = "seed is passed by value so uniffi 0.32 maps it to a `RustBuffer` (Kotlin `ByteArray` / Swift `Data`) rather than the non-`Send` `ForeignBytes` view produced for `&[u8]`"
    )]
    pub fn danger_sign_challenge(
        &self,
        challenge: Vec<u8>,
    ) -> Result<Vec<u8>, WalletKitError> {
        let signature = self.inner.danger_sign_challenge(&challenge)?;
        Ok(signature.as_bytes().to_vec())
    }

    /// Signs the EIP-712 `InitiateRecoveryAgentUpdate` payload and returns the
    /// raw signature bytes and signing nonce without submitting anything to the
    /// gateway.
    ///
    /// Callers can use the returned bytes to build and submit the gateway
    /// request themselves.
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

    /// Updates the holder's recovery agent (WIP-102).
    ///
    /// On a V2 registry the new agent becomes effective immediately, but for a
    /// revert window any authenticator can call
    /// [`Self::revert_recovery_agent_update`] to roll back. During that window
    /// the *previous* agent remains the only valid signer for `recoverAccount`,
    /// which mitigates a compromised authenticator silently swapping in an
    /// attacker-controlled recovery address.
    ///
    /// # Arguments
    /// * `new_recovery_agent` — the checksummed hex address of the new recovery
    ///   agent (e.g. `"0x1234…"`).
    ///
    /// # Errors
    /// - Returns [`WalletKitError::InvalidInput`] if `new_recovery_agent` is not
    ///   a valid address.
    /// - Returns a network error if the gateway request fails.
    pub async fn update_recovery_agent(
        &self,
        new_recovery_agent: String,
    ) -> Result<String, WalletKitError> {
        let new_recovery_agent =
            Address::parse_from_ffi(&new_recovery_agent, "new_recovery_agent")?;

        let request_id = self.inner.update_recovery_agent(new_recovery_agent).await?;

        Ok(request_id.to_string())
    }

    /// Reverts an in-flight recovery agent update during the revert window
    /// (WIP-102).
    ///
    /// Must be called within the revert window after
    /// [`Self::update_recovery_agent`]. During that window any authenticator
    /// can revert the update; the previous recovery agent stays effective
    /// until the window expires.
    ///
    /// Signs an EIP-712 `CancelRecoveryAgentUpdate` payload (the typehash is
    /// reused on V2) and submits it to the gateway.
    ///
    /// # Errors
    /// Returns a network error if the gateway request fails.
    pub async fn revert_recovery_agent_update(&self) -> Result<String, WalletKitError> {
        let request_id = self.inner.revert_recovery_agent_update().await?;

        Ok(request_id.to_string())
    }

    /// Inserts an authenticator into the holder's World ID account.
    ///
    /// # Arguments
    /// * `new_authenticator_pubkey` — a compressed `BabyJubJub` public key encoded
    ///   as a `0x`-prefixed, zero-padded 32-byte hex string.
    /// * `new_authenticator_address` — the Ethereum address associated with the
    ///   new authenticator. Callers may pass the zero address for a proving-only
    ///   authenticator.
    ///
    /// # Errors
    /// - Returns [`WalletKitError::InvalidInput`] if the public key or address is
    ///   invalid.
    /// - Returns a network error if an indexer or gateway request fails.
    #[tracing::instrument(
        target = "walletkit_latency",
        name = "gateway_insert_authenticator",
        skip_all
    )]
    pub async fn insert_authenticator(
        &self,
        new_authenticator_pubkey: String,
        new_authenticator_address: String,
    ) -> Result<String, WalletKitError> {
        let new_authenticator_pubkey = parse_authenticator_pubkey(
            "new_authenticator_pubkey",
            new_authenticator_pubkey,
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

    /// Returns whether the holder's account already contains an authenticator
    /// public key.
    ///
    /// This performs a read-only indexer fetch and does not submit an account
    /// operation.
    ///
    /// # Arguments
    /// * `authenticator_pubkey` — a compressed `BabyJubJub` public key encoded
    ///   as a `0x`-prefixed, zero-padded 32-byte hex string.
    ///
    /// # Errors
    /// - Returns [`WalletKitError::InvalidInput`] if the public key is invalid.
    /// - Returns a network error if the indexer request fails.
    #[tracing::instrument(
        target = "walletkit_latency",
        name = "indexer_authenticator_pubkeys",
        skip_all
    )]
    pub async fn has_authenticator_pubkey(
        &self,
        authenticator_pubkey: String,
    ) -> Result<bool, WalletKitError> {
        let authenticator_pubkey =
            parse_authenticator_pubkey("authenticator_pubkey", authenticator_pubkey)?;
        let pubkeys = self.inner.fetch_authenticator_pubkeys().await?;
        Ok(pubkeys
            .iter()
            .flatten()
            .any(|existing_pubkey| existing_pubkey == &authenticator_pubkey))
    }

    /// Returns the account's authenticator public keys, indexed by key-set slot.
    ///
    /// Each entry is the compressed `BabyJubJub` public key at that slot encoded
    /// as a `0x`-prefixed, zero-padded 32-byte hex string, or `None` for an
    /// empty slot. A key's position in this list is the `pubkey_id` expected by
    /// [`Self::remove_authenticator`].
    ///
    /// This performs a read-only indexer fetch and does not submit an account
    /// operation.
    ///
    /// # Errors
    /// - Returns a network error if the indexer request fails.
    /// - Returns an error if a stored public key cannot be encoded.
    #[tracing::instrument(
        target = "walletkit_latency",
        name = "indexer_authenticator_pubkeys",
        skip_all
    )]
    pub async fn get_authenticator_pubkeys(
        &self,
    ) -> Result<Vec<Option<String>>, WalletKitError> {
        let key_set = self.inner.fetch_authenticator_pubkeys().await?;
        key_set
            .iter()
            .map(|slot| {
                slot.as_ref()
                    .map(|pubkey| {
                        let encoded = pubkey.to_ethereum_representation()?;
                        Ok(format!("{encoded:#066x}"))
                    })
                    .transpose()
            })
            .collect()
    }

    /// Removes an authenticator from the holder's World ID account.
    ///
    /// # Arguments
    /// * `authenticator_address` — the Ethereum address associated with the
    ///   authenticator being removed. Callers must pass the zero address for a
    ///   proving-only authenticator.
    /// * `pubkey_id` — the stable key-set slot of the authenticator being removed.
    /// * `expected_authenticator_pubkey` — the compressed `BabyJubJub` public key
    ///   the caller intends to remove, encoded as a `0x`-prefixed, zero-padded
    ///   32-byte hex string. The removal is refused if `pubkey_id` currently
    ///   holds a different key, catching callers acting on a stale key-set view
    ///   (see [`Self::get_authenticator_pubkeys`]). This check is best-effort:
    ///   the signing flow re-reads the key set afterwards, so a concurrent
    ///   change to the slot between the check and that read can still remove
    ///   whichever key the slot holds at signing time. Callers that need an
    ///   exact-target guarantee must serialize account operations across the
    ///   account's authenticators.
    ///
    /// # Errors
    /// - Returns [`WalletKitError::InvalidInput`] if the address or public key
    ///   is invalid, if `pubkey_id` is out of range, if the slot is empty, or
    ///   if the slot holds a different key.
    /// - Returns a network error if an indexer or gateway request fails.
    #[tracing::instrument(
        target = "walletkit_latency",
        name = "gateway_remove_authenticator",
        skip_all
    )]
    pub async fn remove_authenticator(
        &self,
        authenticator_address: String,
        pubkey_id: u32,
        expected_authenticator_pubkey: String,
    ) -> Result<String, WalletKitError> {
        let expected_pubkey = parse_authenticator_pubkey(
            "expected_authenticator_pubkey",
            expected_authenticator_pubkey,
        )?;
        let authenticator_address =
            Address::parse_from_ffi(&authenticator_address, "authenticator_address")?;

        if pubkey_id as usize >= MAX_AUTHENTICATOR_KEYS {
            return Err(WalletKitError::InvalidInput {
                attribute: "pubkey_id".to_string(),
                reason: format!(
                    "pubkey_id {pubkey_id} is out of range; the key set has at \
                     most {MAX_AUTHENTICATOR_KEYS} slots"
                ),
            });
        }

        let empty_slot = || WalletKitError::InvalidInput {
            attribute: "pubkey_id".to_string(),
            reason: format!("no authenticator at key set slot {pubkey_id}"),
        };
        let key_set = self.inner.fetch_authenticator_pubkeys().await?;
        let actual_pubkey = key_set.get(pubkey_id as usize).ok_or_else(empty_slot)?;
        if actual_pubkey != &expected_pubkey {
            return Err(WalletKitError::InvalidInput {
                attribute: "expected_authenticator_pubkey".to_string(),
                reason: format!(
                    "key set slot {pubkey_id} holds a different authenticator public key"
                ),
            });
        }

        let request_id = self
            .inner
            .remove_authenticator(authenticator_address, pubkey_id)
            .await
            .map_err(|error| match error {
                // The slot emptied between the check above and the crate's own
                // signing read; report it as the input problem it is rather
                // than an authorization failure.
                AuthenticatorError::PublicKeyNotFound => empty_slot(),
                other => other.into(),
            })?;

        Ok(request_id.to_string())
    }

    /// Polls the gateway once for the status of an account operation.
    ///
    /// # Errors
    /// Returns a network error if the gateway request fails.
    #[tracing::instrument(
        target = "walletkit_latency",
        name = "gateway_poll",
        skip_all
    )]
    pub async fn poll_status(
        &self,
        request_id: String,
    ) -> Result<GatewayRequestStatus, WalletKitError> {
        let request_id = GatewayRequestId::new(
            request_id.strip_prefix("gw_").unwrap_or(&request_id),
        );
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
        seed: Vec<u8>,
        rpc_url: Option<String>,
        environment: &Environment,
        region: Option<Region>,
        artifacts: Arc<dyn WalletKitZkArtifactSource>,
        store: Arc<CredentialStore>,
    ) -> Result<Self, WalletKitError> {
        let config = defaults::default_config(environment, rpc_url, region)?;
        Self::init_with_config(&seed, config, artifacts, store).await
    }

    /// Initializes a new Authenticator from a seed using SDK defaults routed
    /// through the OHTTP relay. Opt-in alternative to
    /// [`Authenticator::init_with_defaults`].
    ///
    /// The user's World ID must already be registered in the `WorldIDRegistry`,
    /// otherwise a [`WalletKitError::AccountDoesNotExist`] error will be returned.
    ///
    /// # Errors
    /// See `CoreAuthenticator::init` for potential errors.
    #[uniffi::constructor]
    #[tracing::instrument(target = "walletkit_latency", name = "rpc_init", skip_all)]
    pub async fn init_with_ohttp_defaults(
        seed: Vec<u8>,
        rpc_url: Option<String>,
        environment: &Environment,
        region: Option<Region>,
        artifacts: Arc<dyn WalletKitZkArtifactSource>,
        store: Arc<CredentialStore>,
    ) -> Result<Self, WalletKitError> {
        let config = defaults::default_config_with_ohttp(environment, rpc_url, region)?;
        Self::init_with_config(&seed, config, artifacts, store).await
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
        seed: Vec<u8>,
        config: &str,
        artifacts: Arc<dyn WalletKitZkArtifactSource>,
        store: Arc<CredentialStore>,
    ) -> Result<Self, WalletKitError> {
        let config =
            Config::from_json(config).map_err(|_| WalletKitError::InvalidInput {
                attribute: "config".to_string(),
                reason: "Invalid config".to_string(),
            })?;
        Self::init_with_config(&seed, config, artifacts, store).await
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

        // Cache session seed if returned. Create-session requests do not carry a
        // session_id, so use the session_id generated in the proof response.
        if let Some(seed) = result.session_id_r_seed {
            if let Some(session_id) = result.proof_response.session_id {
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

/// Status of an account operation submitted through the gateway.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
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
                error_code: error_code.map(|code| code.to_string()),
            },
        }
    }
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
        seed: Vec<u8>,
        rpc_url: Option<String>,
        environment: &Environment,
        region: Option<Region>,
        recovery_address: Option<String>,
    ) -> Result<Self, WalletKitError> {
        let recovery_address =
            Address::parse_from_ffi_optional(recovery_address, "recovery_address")?;

        let config = defaults::default_config(environment, rpc_url, region)?;

        let initializing_authenticator =
            CoreAuthenticator::register(&seed, config, recovery_address).await?;

        Ok(Self(initializing_authenticator))
    }

    /// Registers a new World ID using SDK defaults routed through the OHTTP
    /// relay. Opt-in alternative to
    /// [`InitializingAuthenticator::register_with_defaults`].
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
    pub async fn register_with_ohttp_defaults(
        seed: Vec<u8>,
        rpc_url: Option<String>,
        environment: &Environment,
        region: Option<Region>,
        recovery_address: Option<String>,
    ) -> Result<Self, WalletKitError> {
        let recovery_address =
            Address::parse_from_ffi_optional(recovery_address, "recovery_address")?;

        let config = defaults::default_config_with_ohttp(environment, rpc_url, region)?;

        let initializing_authenticator =
            CoreAuthenticator::register(&seed, config, recovery_address).await?;

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
        seed: Vec<u8>,
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
            CoreAuthenticator::register(&seed, config, recovery_address).await?;

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

/// Validates an authenticator public key without submitting an account
/// operation, returning its canonical encoding.
///
/// This is a free function (not a method on [`Authenticator`]) so consumers
/// can validate a key — e.g. one scanned during pairing — before an
/// `Authenticator` exists.
///
/// The returned string is the canonical form of the key (lowercase,
/// `0x`-prefixed, zero-padded 32-byte hex), byte-identical to the entries
/// returned by [`Authenticator::get_authenticator_pubkeys`]. Use it — not the
/// raw input — for string comparisons against key-set entries.
///
/// # Arguments
/// * `authenticator_pubkey` — a compressed `BabyJubJub` public key encoded
///   as a `0x`-prefixed, zero-padded 32-byte hex string.
///
/// # Errors
/// Returns [`WalletKitError::InvalidInput`] if the public key is invalid,
/// is not in canonical form, or is the `BabyJubJub` identity point.
#[uniffi::export]
pub fn validate_authenticator_pubkey(
    authenticator_pubkey: &str,
) -> Result<String, WalletKitError> {
    let pubkey =
        parse_authenticator_pubkey("authenticator_pubkey", authenticator_pubkey)?;
    let encoded = pubkey.to_ethereum_representation()?;
    Ok(format!("{encoded:#066x}"))
}

/// Derives recovery data from a 32-byte seed.
///
/// This is the foreign-bindings entrypoint for recovery data generation.
///
/// # Errors
/// Returns [`WalletKitError`] if the seed is invalid or serialization fails.
#[uniffi::export]
#[allow(
    clippy::needless_pass_by_value,
    reason = "seed is passed by value so uniffi 0.32 maps it to a `RustBuffer` (Kotlin `ByteArray` / Swift `Data`) rather than the non-`Send` `ForeignBytes` view produced for `&[u8]`"
)]
pub fn recovery_data_from_seed(seed: Vec<u8>) -> Result<RecoveryData, WalletKitError> {
    RecoveryData::from_seed(&seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SEED: [u8; 32] = [1u8; 32];

    async fn test_authenticator(
        server: &mut mockito::Server,
    ) -> (Authenticator, std::path::PathBuf) {
        use crate::storage::tests_utils::{temp_root_path, InMemoryStorageProvider};
        use alloy::primitives::address;
        use world_id_core::primitives::ServiceEndpoint;
        use world_id_proof::artifacts::dummy::DummyZkArtifactSource;

        let _ = rustls::crypto::ring::default_provider().install_default();

        let packed_account_mock = server
            .mock("POST", "/packed-account")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(serde_json::json!({ "packed_account_data": "0x2a" }).to_string())
            .create_async()
            .await;
        let config = Config::new(
            None,
            480,
            address!("0x969947cFED008bFb5e3F32a25A1A2CDdf64d46fe"),
            ServiceEndpoint::direct(server.url()),
            ServiceEndpoint::direct(server.url()),
            vec![],
            2,
        )
        .expect("valid config");
        let root = temp_root_path();
        let provider = InMemoryStorageProvider::new(&root);
        let store =
            CredentialStore::from_provider(&provider).expect("credential store");
        let authenticator = Authenticator::init_with_config(
            &TEST_SEED,
            config,
            Arc::new(DummyZkArtifactSource),
            Arc::new(store),
        )
        .await
        .expect("authenticator should initialize");
        packed_account_mock.assert_async().await;

        (authenticator, root)
    }

    fn encoded_pubkey(seed: &[u8; 32]) -> String {
        let pubkey = Signer::from_seed_bytes(seed)
            .expect("valid seed")
            .offchain_signer_pubkey()
            .to_ethereum_representation()
            .expect("public key should encode");
        format!("{pubkey:#066x}")
    }

    /// Mocks the indexer's `/authenticator-pubkeys` endpoint with a fixed
    /// key-set response (`None` entries are empty slots), asserting the
    /// request body and the expected number of hits.
    async fn mock_authenticator_pubkeys(
        server: &mut mockito::Server,
        pubkeys: &[Option<&str>],
        expected_hits: usize,
    ) -> mockito::Mock {
        server
            .mock("POST", "/authenticator-pubkeys")
            .match_body(mockito::Matcher::JsonString(
                serde_json::json!({ "leaf_index": "0x2a" }).to_string(),
            ))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                serde_json::json!({
                    "authenticator_pubkeys": pubkeys,
                    "offchain_signer_commitment": "0x0"
                })
                .to_string(),
            )
            .expect(expected_hits)
            .create_async()
            .await
    }

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
    fn test_authenticator_pubkey_validation() {
        let canonical = encoded_pubkey(&[2u8; 32]);
        assert_eq!(
            validate_authenticator_pubkey(&canonical).expect("valid key"),
            canonical
        );
        let uppercase = format!("0x{}", canonical[2..].to_uppercase());
        assert_eq!(
            validate_authenticator_pubkey(&uppercase)
                .expect("uppercase hex should canonicalize"),
            canonical
        );

        for invalid_pubkey in [
            "not-a-public-key".to_string(),
            format!("0x{}", "ff".repeat(32)),
        ] {
            assert!(matches!(
                validate_authenticator_pubkey(&invalid_pubkey),
                Err(WalletKitError::InvalidInput { attribute, .. })
                    if attribute == "authenticator_pubkey"
            ));
        }

        let identity = format!("0x{}01", "0".repeat(62));
        assert!(matches!(
            validate_authenticator_pubkey(&identity),
            Err(WalletKitError::InvalidInput { attribute, reason })
                if attribute == "authenticator_pubkey" && reason.contains("identity")
        ));
        let sign_bit_alias = format!("0x80{}01", "0".repeat(60));
        assert!(matches!(
            validate_authenticator_pubkey(&sign_bit_alias),
            Err(WalletKitError::InvalidInput { attribute, reason })
                if attribute == "authenticator_pubkey" && reason.contains("canonical")
        ));
    }

    #[tokio::test]
    async fn test_poll_status_normalizes_request_id() {
        use crate::storage::tests_utils::cleanup_test_storage;

        let mut server = mockito::Server::new_async().await;
        let (authenticator, root) = test_authenticator(&mut server).await;
        let status_mock = server
            .mock("GET", "/status/gw_poll_test")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                serde_json::json!({
                    "request_id": "gw_poll_test",
                    "kind": "insert_authenticator",
                    "status": {
                        "state": "finalized",
                        "tx_hash": "0x1234"
                    }
                })
                .to_string(),
            )
            .expect(2)
            .create_async()
            .await;

        for request_id in ["poll_test", "gw_poll_test"] {
            assert_eq!(
                authenticator
                    .poll_status(request_id.to_string())
                    .await
                    .expect("status poll should succeed"),
                GatewayRequestStatus::Finalized {
                    tx_hash: "0x1234".to_string()
                }
            );
        }
        status_mock.assert_async().await;

        drop(server);
        cleanup_test_storage(&root);
    }

    #[tokio::test]
    async fn test_remove_authenticator_refuses_unexpected_slot_contents() {
        use crate::storage::tests_utils::cleanup_test_storage;

        let mut server = mockito::Server::new_async().await;
        let (authenticator, root) = test_authenticator(&mut server).await;
        let existing_pubkey = encoded_pubkey(&TEST_SEED);
        let slot_pubkey = encoded_pubkey(&[2u8; 32]);

        let pubkeys_mock = mock_authenticator_pubkeys(
            &mut server,
            &[
                Some(existing_pubkey.as_str()),
                None,
                Some(slot_pubkey.as_str()),
            ],
            2,
        )
        .await;
        let nonce_mock = server
            .mock("POST", "/signature-nonce")
            .expect(0)
            .create_async()
            .await;
        let remove_mock = server
            .mock("POST", "/remove-authenticator")
            .expect(0)
            .create_async()
            .await;

        let mismatched = authenticator
            .remove_authenticator(
                Address::ZERO.to_string(),
                2,
                encoded_pubkey(&[3u8; 32]),
            )
            .await;
        assert!(matches!(
            mismatched,
            Err(WalletKitError::InvalidInput { attribute, .. })
                if attribute == "expected_authenticator_pubkey"
        ));

        let empty_slot = authenticator
            .remove_authenticator(
                Address::ZERO.to_string(),
                1,
                encoded_pubkey(&[3u8; 32]),
            )
            .await;
        assert!(matches!(
            empty_slot,
            Err(WalletKitError::InvalidInput { attribute, reason })
                if attribute == "pubkey_id"
                    && reason.contains("no authenticator at key set slot 1")
        ));

        let out_of_range = authenticator
            .remove_authenticator(
                Address::ZERO.to_string(),
                7,
                encoded_pubkey(&[3u8; 32]),
            )
            .await;
        assert!(matches!(
            out_of_range,
            Err(WalletKitError::InvalidInput { attribute, reason })
                if attribute == "pubkey_id" && reason.contains("out of range")
        ));

        pubkeys_mock.assert_async().await;
        nonce_mock.assert_async().await;
        remove_mock.assert_async().await;

        drop(server);
        cleanup_test_storage(&root);
    }

    #[tokio::test]
    async fn test_key_set_reads_return_slots_and_membership() {
        use crate::storage::tests_utils::cleanup_test_storage;

        let mut server = mockito::Server::new_async().await;
        let (authenticator, root) = test_authenticator(&mut server).await;
        let existing_pubkey = encoded_pubkey(&TEST_SEED);
        let other_pubkey = encoded_pubkey(&[2u8; 32]);

        let pubkeys_mock = mock_authenticator_pubkeys(
            &mut server,
            &[
                Some(existing_pubkey.as_str()),
                None,
                Some(other_pubkey.as_str()),
            ],
            3,
        )
        .await;

        assert!(authenticator
            .has_authenticator_pubkey(existing_pubkey.clone())
            .await
            .expect("membership read should succeed"));
        assert!(!authenticator
            .has_authenticator_pubkey(encoded_pubkey(&[3u8; 32]))
            .await
            .expect("absent key check should succeed"));
        assert_eq!(
            authenticator
                .get_authenticator_pubkeys()
                .await
                .expect("key set read should succeed"),
            vec![Some(existing_pubkey), None, Some(other_pubkey)]
        );
        pubkeys_mock.assert_async().await;

        drop(server);
        cleanup_test_storage(&root);
    }

    #[tokio::test]
    async fn test_remove_authenticator_reports_slot_emptied_during_signing() {
        use crate::storage::tests_utils::cleanup_test_storage;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let mut server = mockito::Server::new_async().await;
        let (authenticator, root) = test_authenticator(&mut server).await;
        let existing_pubkey = encoded_pubkey(&TEST_SEED);
        let removed_pubkey = encoded_pubkey(&[2u8; 32]);

        // The first read (the wrapper's guard) sees the key at slot 1; the
        // second read (the crate's own signing fetch) sees the slot already
        // emptied, as if a concurrent operation landed in between. The
        // `PublicKeyNotFound` this produces must surface as the `pubkey_id`
        // input error, not as an authorization failure.
        let full_body = serde_json::json!({
            "authenticator_pubkeys": [existing_pubkey.clone(), removed_pubkey.clone()],
            "offchain_signer_commitment": "0x0"
        })
        .to_string();
        let emptied_body = serde_json::json!({
            "authenticator_pubkeys": [existing_pubkey],
            "offchain_signer_commitment": "0x0"
        })
        .to_string();
        let fetches = Arc::new(AtomicUsize::new(0));
        let fetches_in_mock = Arc::clone(&fetches);
        let pubkeys_mock = server
            .mock("POST", "/authenticator-pubkeys")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body_from_request(move |_request| {
                if fetches_in_mock.fetch_add(1, Ordering::SeqCst) == 0 {
                    full_body.clone().into_bytes()
                } else {
                    emptied_body.clone().into_bytes()
                }
            })
            .expect(2)
            .create_async()
            .await;
        let nonce_mock = server
            .mock("POST", "/signature-nonce")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(serde_json::json!({ "signature_nonce": "0x1" }).to_string())
            .create_async()
            .await;
        let remove_mock = server
            .mock("POST", "/remove-authenticator")
            .expect(0)
            .create_async()
            .await;

        let raced = authenticator
            .remove_authenticator(Address::ZERO.to_string(), 1, removed_pubkey)
            .await;
        assert!(matches!(
            raced,
            Err(WalletKitError::InvalidInput { attribute, .. })
                if attribute == "pubkey_id"
        ));

        pubkeys_mock.assert_async().await;
        nonce_mock.assert_async().await;
        remove_mock.assert_async().await;

        drop(server);
        cleanup_test_storage(&root);
    }

    #[cfg(feature = "embed-zkeys")]
    #[tokio::test]
    async fn test_init_with_config_and_materials() {
        use crate::{
            authenticator::artifacts::caching::CachingZkArtifacts,
            storage::tests_utils::{
                cleanup_test_storage, temp_root_path, InMemoryStorageProvider,
            },
        };
        use alloy::primitives::address;
        use world_id_core::primitives::{Config, ServiceEndpoint};

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
            ServiceEndpoint::direct(
                "https://indexer.us.id-infra.worldcoin.dev".to_string(),
            ),
            ServiceEndpoint::direct(
                "https://gateway.id-infra.worldcoin.dev".to_string(),
            ),
            vec![],
            2,
        )
        .unwrap();
        let config = serde_json::to_string(&config).unwrap();

        let root = temp_root_path();
        let provider = InMemoryStorageProvider::new(&root);
        let store = CredentialStore::from_provider(&provider).expect("store");
        store.init(42, 100).expect("init storage");

        let artifacts =
            Arc::new(CachingZkArtifacts::new(Arc::new(store.paths().unwrap())));

        let _authenticator =
            Authenticator::init([2u8; 32].to_vec(), &config, artifacts, Arc::new(store))
                .await
                .unwrap();
        drop(mock_server);

        cleanup_test_storage(&root);
    }
}
