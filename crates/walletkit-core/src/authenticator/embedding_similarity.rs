//! Proves a WIP-202 Proof of Embedding Similarity: billing, the Flamingo exchange and the proof.

use std::sync::Arc;

use alloy_core::primitives::Address;
use flamingo_verifier_client::VerifiedMatchResult;
use world_id_core::{
    primitives::billing::BillingWitness, EmbeddingSimilarityImages, FieldElement,
    FlamingoResult,
};
use world_id_flamingo::FlamingoToken;

use super::{billing_registration::requested_credential, resolve_now, Authenticator};
use crate::error::WalletKitError;
use crate::flamingo::{FlamingoDebugReport, FlamingoMatchRejection, FlamingoMatcher};
use crate::primitives::ParseFromForeignBinding;
use crate::requests::{ProofRequest, ProofRequestType, ProofResponse};

/// What the app supplies for a Proof of Embedding Similarity, besides the request.
///
/// `WalletKit` keeps no Personal Custody Package, so the app reads the Credential image and its
/// `hashes.json` from it for each proof.
#[derive(uniffi::Record)]
pub struct EmbeddingSimilarityInputs {
    /// The PCP thumbnail that `hashes_json` lists.
    pub credential_image: Vec<u8>,
    /// The PCP's Orb-signed `hashes.json`, to which the `PoH` Credential's claim 0 commits.
    pub hashes_json: Vec<u8>,
    /// The live capture.
    pub live_capture: Vec<u8>,
    /// The RP's challenge image, which must hash to the request's `challenge_hash`.
    pub challenge: Vec<u8>,
}

/// Omits the images, which are biometric data.
impl std::fmt::Debug for EmbeddingSimilarityInputs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmbeddingSimilarityInputs")
            .finish_non_exhaustive()
    }
}

/// The outcome of a Proof of Embedding Similarity.
#[derive(Debug, uniffi::Enum)]
pub enum EmbeddingSimilarityOutcome {
    /// The Engine passed and the proof was generated.
    Proven {
        /// The response for the RP.
        response: Arc<ProofResponse>,
        /// Engine diagnostics, not covered by the proof.
        debug_report: FlamingoDebugReport,
    },
    /// The Verifier reported a rejection, so no proof was generated.
    Rejected {
        /// Structured input or biometric rejection.
        reason: FlamingoMatchRejection,
        /// Engine diagnostics, if produced before rejection.
        debug_report: FlamingoDebugReport,
    },
}

#[uniffi::export(async_runtime = "tokio")]
impl Authenticator {
    /// Generates a Proof of Embedding Similarity (WIP-202) for `proof_request`.
    ///
    /// If `billing_contract` bills the request's RP, the World ID first registers with it
    /// (WIP-107), unless a registration is cached. `matcher` then compares the Credential image,
    /// the live capture and the challenge on an attested Flamingo Verifier, and the proof is
    /// generated from its token. The session's `r` seed is cached like [`Self::generate_proof`]'s.
    ///
    /// # Arguments
    /// * `proof_request` — the RP's Proof of Embedding Similarity request.
    /// * `matcher` — a Flamingo Verifier client with a trusted Engine Provider.
    /// * `inputs` — the PCP's Credential image and `hashes.json`, the live capture and the
    ///   challenge.
    /// * `match_strictness` — the Authenticator Provider's match strictness level, which the
    ///   attested release must offer.
    /// * `billing_contract` — the environment's WIP-107 Billing Contract (see
    ///   `Environment::billing_contract_address`), or `None` to bill no RP.
    /// * `now` — the current Unix time in seconds; the system clock if `None`.
    ///
    /// # Errors
    /// - [`WalletKitError::InvalidInput`] if the request is not a Proof of Embedding Similarity
    ///   request or `billing_contract` is not an address.
    /// - [`WalletKitError::UnfulfillableRequest`] if no stored, unexpired credential is the one the
    ///   request asks for. This is checked before any network call.
    /// - [`WalletKitError::BillingCapacityExhausted`] and other errors of the billing registration.
    /// - [`WalletKitError::Flamingo`] if the Flamingo exchange fails.
    /// - Other errors if the inclusion proof, the OPRF Nodes or proof generation fail.
    pub async fn generate_embedding_similarity_proof(
        &self,
        proof_request: &ProofRequest,
        matcher: &FlamingoMatcher,
        inputs: EmbeddingSimilarityInputs,
        match_strictness: u8,
        billing_contract: Option<String>,
        now: Option<u64>,
    ) -> Result<EmbeddingSimilarityOutcome, WalletKitError> {
        let fixed_now = now;
        if proof_request.proof_type() != ProofRequestType::EmbeddingSimilarity {
            return Err(WalletKitError::InvalidInput {
                attribute: "proof_type".to_string(),
                reason: "must be embedding_similarity".to_string(),
            });
        }
        let billing_contract = billing_contract
            .map(|address| Address::parse_from_ffi(&address, "billing_contract"))
            .transpose()?;
        let now = resolve_now(now)?;
        let request = &proof_request.0;
        let credential = requested_credential(
            self.stored_credentials(now)?,
            request.requests.first().map(|item| item.issuer_schema_id),
        )?;

        let billing = match billing_contract {
            Some(billing_contract) => {
                self.billing_witness(proof_request, billing_contract, now)
                    .await?
            }
            None => None,
        };
        // TODO: Once the Verifier checks registrations, retry once when it reports a fresh one
        // missing (its follower lags the chain), and re-register after dropping the cached witness
        // when it stays missing (a reorg dropped it).
        let billing_nullifier = billing
            .as_ref()
            .map_or(FieldElement::ZERO, |witness| witness.billing_nullifier);

        let account_inclusion_proof =
            self.fetch_inclusion_proof_with_cache(now).await?;
        // A registration can take minutes, so the request's expiry starts from a fresh clock.
        let match_now = resolve_now(fixed_now)?;
        let images = EmbeddingSimilarityImages {
            credential_image: inputs.credential_image,
            live_capture: inputs.live_capture,
            challenge: inputs.challenge,
        };
        let (verified, debug_report) = match matcher
            .match_embedding_similarity(
                request,
                match_strictness,
                &images,
                billing_nullifier,
                match_now,
            )
            .await?
        {
            VerifiedMatchResult::Success {
                verified,
                debug_report,
            } => (verified, debug_report),
            VerifiedMatchResult::Failed {
                reason,
                debug_report,
            } => {
                return Ok(EmbeddingSimilarityOutcome::Rejected {
                    reason: reason.into(),
                    debug_report: debug_report.into(),
                })
            }
        };
        let flamingo = FlamingoResult {
            token: FlamingoToken::from_cwt(&verified.statement.token).map_err(
                |error| WalletKitError::Generic {
                    error: format!(
                        "the verified Flamingo Token does not decode: {error}"
                    ),
                },
            )?,
            verifier_key: verified.verifier_key,
            signing_key_attestation: verified.statement.signing_key_attestation.into(),
        };

        let session_id_r_seed = self.cached_session_seed(request, now);
        // Box::pin keeps this future below clippy::large_futures, as in generate_proof.
        let result = Box::pin(self.inner.generate_embedding_similarity_proof(
            request,
            &flamingo,
            &credential,
            &inputs.hashes_json,
            billing.as_ref(),
            Some(account_inclusion_proof),
            session_id_r_seed,
        ))
        .await?;
        self.cache_session_seed(request.rp_id.into_inner(), &result, now);

        Ok(EmbeddingSimilarityOutcome::Proven {
            response: Arc::new(result.proof_response.into()),
            debug_report: debug_report.into(),
        })
    }
}

impl Authenticator {
    /// The billing witness for the request's RP, registering first if needed, or `None` if
    /// `billing_contract` does not bill the RP.
    async fn billing_witness(
        &self,
        proof_request: &ProofRequest,
        billing_contract: Address,
        now: u64,
    ) -> Result<Option<BillingWitness>, WalletKitError> {
        let rp_id = proof_request.0.rp_id.into_inner();
        let billed = self.fetch_billed_rps(billing_contract, now).await?;
        if !billed.snapshot.is_billed(rp_id) {
            return Ok(None);
        }
        self.ensure_billing_registration(proof_request, billing_contract, now)
            .await
            .map(Some)
    }
}
