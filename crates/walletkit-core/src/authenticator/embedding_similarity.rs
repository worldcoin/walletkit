//! Proves a WIP-202 Proof of Embedding Similarity: billing, the Flamingo exchange and the proof.

use std::sync::Arc;

use alloy_core::primitives::Address;
use backon::BackoffBuilder as _;
use flamingo_verifier_client::VerifiedMatchResult;
use flamingo_verifier_sealed_types::FailureReason;
use world_id_core::{
    primitives::billing::BillingWitness, EmbeddingSimilarityImages, FieldElement,
    FlamingoResult,
};
use world_id_flamingo::FlamingoToken;

use super::{billing_registration::requested_credential, resolve_now, Authenticator};
use crate::error::WalletKitError;
use crate::flamingo::{
    EmbeddingSimilarityMatch, FlamingoDebugReport, FlamingoMatchRejection,
    FlamingoMatcher,
};
use crate::primitives::ParseFromForeignBinding;
use crate::registration::{polling_backoff, sleep};
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

        let account_inclusion_proof =
            self.fetch_inclusion_proof_with_cache(now).await?;
        let images = EmbeddingSimilarityImages {
            credential_image: inputs.credential_image,
            live_capture: inputs.live_capture,
            challenge: inputs.challenge,
        };
        let (exchanged, billing) = self
            .match_billed(
                &BilledExchange {
                    proof_request,
                    matcher,
                    images: &images,
                    match_strictness,
                    billing_contract,
                    fixed_now,
                },
                billing,
            )
            .await?;
        let (verified, debug_report) = match exchanged.result {
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
            nonce_salt: exchanged.nonce_salt,
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

/// How often a Verifier may report a fresh registration missing before the World ID registers
/// again. Its billing state follows the chain within about a block, so this covers the lag.
const UNREGISTERED_RETRIES: u32 = 2;

/// What every Flamingo request of one Proof of Embedding Similarity shares.
struct BilledExchange<'a> {
    proof_request: &'a ProofRequest,
    matcher: &'a FlamingoMatcher,
    images: &'a EmbeddingSimilarityImages,
    match_strictness: u8,
    billing_contract: Option<Address>,
    fixed_now: Option<u64>,
}

impl Authenticator {
    /// Runs the Flamingo exchange, recovering from the Verifier's billing rejections
    /// (WIP-107 §4.6), and returns its last result with the billing witness it carried.
    ///
    /// Every request is new, with a fresh `nonce` (WIP-201 §4.6), and the Verifier rejects billing
    /// before the Engine runs, so a resent request costs no inference:
    /// - `billing_unregistered`: the Verifier has not seen the registration yet, so the request is
    ///   resent with backoff, up to [`UNREGISTERED_RETRIES`] times.
    /// - `billing_nullifier_required`, or a registration that stays missing: the billed-RP
    ///   snapshot was stale or a reorg dropped the registration, so the World ID registers again,
    ///   once, and resends.
    ///
    /// Any other result, including a failed capture, is returned for the app to handle.
    async fn match_billed(
        &self,
        exchange: &BilledExchange<'_>,
        mut billing: Option<BillingWitness>,
    ) -> Result<(EmbeddingSimilarityMatch, Option<BillingWitness>), WalletKitError>
    {
        let rp_id = exchange.proof_request.0.rp_id;
        let mut delays = polling_backoff().build();
        let mut unregistered = 0;
        let mut registered_again = false;
        loop {
            let billing_nullifier = billing
                .as_ref()
                .map_or(FieldElement::ZERO, |witness| witness.billing_nullifier);
            // A registration can take minutes, so each request's expiry starts from a fresh clock.
            let matched = exchange
                .matcher
                .match_embedding_similarity(
                    &exchange.proof_request.0,
                    exchange.match_strictness,
                    exchange.images,
                    billing_nullifier,
                    resolve_now(exchange.fixed_now)?,
                )
                .await?;
            let (VerifiedMatchResult::Failed { reason, .. }, Some(billing_contract)) =
                (&matched.result, exchange.billing_contract)
            else {
                return Ok((matched, billing));
            };
            match billing_recovery(reason, unregistered, registered_again) {
                BillingRecovery::Resend => {
                    unregistered += 1;
                    tracing::warn!(
                        %rp_id,
                        attempt = unregistered,
                        "the Flamingo Verifier has not seen the billing registration yet; resending"
                    );
                    if let Some(delay) = delays.next() {
                        sleep(delay).await;
                    }
                }
                BillingRecovery::RegisterAgain => {
                    registered_again = true;
                    unregistered = 0;
                    delays = polling_backoff().build();
                    tracing::warn!(
                        %rp_id,
                        ?reason,
                        "the Flamingo Verifier rejected the billing registration; registering again"
                    );
                    let now = resolve_now(exchange.fixed_now)?;
                    self.forget_billing_registration(
                        exchange.proof_request,
                        billing_contract,
                        now,
                    )?;
                    billing = Some(
                        self.ensure_billing_registration(
                            exchange.proof_request,
                            billing_contract,
                            now,
                        )
                        .await?,
                    );
                }
                BillingRecovery::Stop => return Ok((matched, billing)),
            }
        }
    }

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

/// What to do after the Verifier rejected a request of a billed exchange.
#[derive(Debug, PartialEq, Eq)]
enum BillingRecovery {
    /// Resend after a backoff: the Verifier has not seen a fresh registration yet.
    Resend,
    /// Drop the cached witness, register again and resend.
    RegisterAgain,
    /// Return the rejection.
    Stop,
}

/// The recovery from `reason` after `unregistered` resends since the last registration, and whether
/// the World ID has already registered again in this exchange.
const fn billing_recovery(
    reason: &FailureReason,
    unregistered: u32,
    registered_again: bool,
) -> BillingRecovery {
    match reason {
        FailureReason::BillingUnregistered if unregistered < UNREGISTERED_RETRIES => {
            BillingRecovery::Resend
        }
        FailureReason::BillingNullifierRequired
        | FailureReason::BillingUnregistered
            if !registered_again =>
        {
            BillingRecovery::RegisterAgain
        }
        _ => BillingRecovery::Stop,
    }
}

#[cfg(test)]
mod tests {
    use flamingo_verifier_sealed_types::{ComparisonRole, FailureReason};

    use super::{billing_recovery, BillingRecovery, UNREGISTERED_RETRIES};

    /// Replays the recoveries `match_billed` takes for a Verifier that rejects every request with
    /// `reason`, returning them in order.
    fn recoveries(reason: &FailureReason) -> Vec<BillingRecovery> {
        let (mut unregistered, mut registered_again) = (0, false);
        let mut taken = Vec::new();
        loop {
            let recovery = billing_recovery(reason, unregistered, registered_again);
            match recovery {
                BillingRecovery::Resend => unregistered += 1,
                BillingRecovery::RegisterAgain => {
                    registered_again = true;
                    unregistered = 0;
                }
                BillingRecovery::Stop => return taken,
            }
            taken.push(recovery);
        }
    }

    #[test]
    fn resends_an_unregistered_request_then_registers_again_once() {
        use BillingRecovery::{RegisterAgain, Resend};

        assert_eq!(UNREGISTERED_RETRIES, 2);
        assert_eq!(
            recoveries(&FailureReason::BillingUnregistered),
            [Resend, Resend, RegisterAgain, Resend, Resend],
            "at most six requests, with one registration"
        );
    }

    #[test]
    fn registers_once_when_the_verifier_bills_an_rp_the_snapshot_did_not() {
        assert_eq!(
            recoveries(&FailureReason::BillingNullifierRequired),
            [BillingRecovery::RegisterAgain]
        );
    }

    #[test]
    fn returns_every_other_rejection_to_the_app() {
        for reason in [
            FailureReason::MatchBelowThreshold(ComparisonRole::OrbSelfie),
            FailureReason::Replayed,
            FailureReason::Expired,
            FailureReason::Internal,
        ] {
            assert!(recoveries(&reason).is_empty(), "{reason:?}");
        }
    }
}
