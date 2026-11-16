//! Registers the World ID with a WIP-107 Billing Contract before a billed Proof of Embedding
//! Similarity (§4.6).

use std::time::Duration;

use alloy_core::primitives::{Address, U256};
use backon::BackoffBuilder as _;
use web_time::Instant;
use world_id_core::{
    api_types::{
        GatewayErrorCode, GatewayRequestId, GatewayRequestState, ServiceApiError,
    },
    primitives::billing::{
        active_periods, ActivePeriods, BillingContext, BillingWitness,
    },
    AuthenticatorError, CredentialInput,
};

use super::Authenticator;
use crate::error::WalletKitError;
use crate::registration::{before, polling_backoff, sleep};
use crate::requests::{ProofRequest, ProofRequestType};

/// How long to wait for the gateway to finalize a registration on-chain.
const FINALIZATION_TIMEOUT: Duration = Duration::from_secs(120);

impl Authenticator {
    /// Makes sure this World ID is registered with the Billing Contract at `billing_contract` for
    /// the RP of `proof_request`, a Proof of Embedding Similarity request, and returns the billing
    /// witness its proof needs (WIP-107 §4.6). Call it only for an RP the contract bills.
    ///
    /// A witness cached for either active period answers without a network call. Otherwise the
    /// World ID registers, through the OPRF Nodes and the gateway, for the next period while it is
    /// active, or for the current one if the next has no capacity left. A nullifier the gateway
    /// reports as already registered counts as registered. The witness is cached until its
    /// period ends.
    ///
    /// # Errors
    ///
    /// - [`WalletKitError::InvalidInput`] if `proof_request` is not a Proof of Embedding Similarity
    ///   request.
    /// - [`WalletKitError::UnfulfillableRequest`] if no stored, unexpired credential is the one the
    ///   request asks for. This is checked before any network call.
    /// - [`WalletKitError::BillingCapacityExhausted`] if no active period has capacity left.
    /// - Other errors if the OPRF Nodes, the proof, the gateway or the cache fail, or the
    ///   registration does not finalize within two minutes.
    pub async fn ensure_billing_registration(
        &self,
        proof_request: &ProofRequest,
        billing_contract: Address,
        now: u64,
    ) -> Result<BillingWitness, WalletKitError> {
        if proof_request.proof_type() != ProofRequestType::EmbeddingSimilarity {
            return Err(WalletKitError::InvalidInput {
                attribute: "proof_type".to_string(),
                reason: "billing registration needs an embedding_similarity request"
                    .to_string(),
            });
        }
        let request = &proof_request.0;
        let periods = candidate_periods(active_periods(now)?);
        let scopes: Vec<BillingContext> = periods
            .iter()
            .map(|&period_start| BillingContext {
                chain_id: U256::from(self.inner.config.chain_id()),
                billing_contract,
                rp_id: request.rp_id,
                period_start,
            })
            .collect();

        for scope in &scopes {
            if let Some(witness) =
                self.store
                    .get_billing_witness(scope, request.oprf_key_id, now)?
            {
                return Ok(witness);
            }
        }

        let credential = registration_credential(
            self.stored_credentials(now)?,
            request.requests.first().map(|item| item.issuer_schema_id),
        )?;
        let account_inclusion_proof =
            self.fetch_inclusion_proof_with_cache(now).await?;

        for (index, scope) in scopes.iter().enumerate() {
            // Box::pin keeps this future below clippy::large_futures, as in generate_proof.
            let billing_query = Box::pin(self.inner.generate_billing_nullifier(
                request,
                scope,
                now,
                Some(account_inclusion_proof.clone()),
            ))
            .await?;
            let witness = billing_query.billing_witness();
            let registration = self.inner.generate_billing_registration(
                request,
                scope,
                billing_query,
                &credential,
            )?;

            let outcome =
                match self.inner.submit_billing_registration(&registration).await {
                    Ok(request_id) => self.await_finalization(&request_id).await?,
                    Err(error) => submission_outcome(error)?,
                };
            match outcome {
                Outcome::Registered => {
                    self.store.store_billing_witness(
                        scope,
                        request.oprf_key_id,
                        &witness,
                        now,
                    )?;
                    return Ok(witness);
                }
                Outcome::CapacityExhausted if index + 1 < scopes.len() => {
                    tracing::debug!(
                        rp_id = %request.rp_id,
                        period_start = scope.period_start,
                        "the next billing period has no capacity left; registering for the current one"
                    );
                }
                Outcome::CapacityExhausted => {}
            }
        }
        Err(WalletKitError::BillingCapacityExhausted)
    }

    /// Polls the gateway until it finalizes `request_id`, or reports why it did not, within
    /// [`FINALIZATION_TIMEOUT`]. A poll still in flight at the deadline is abandoned.
    async fn await_finalization(
        &self,
        request_id: &GatewayRequestId,
    ) -> Result<Outcome, WalletKitError> {
        let deadline = Instant::now() + FINALIZATION_TIMEOUT;
        let timed_out = || WalletKitError::Generic {
            error: format!(
                "billing registration {request_id} did not finalize within {}s",
                FINALIZATION_TIMEOUT.as_secs()
            ),
        };
        let mut delays = polling_backoff().build();
        loop {
            let state = before(deadline, self.inner.poll_status(request_id))
                .await
                .ok_or_else(timed_out)??;
            if let Some(outcome) = status_outcome(state)? {
                return Ok(outcome);
            }
            let delay = delays.next().unwrap_or(Duration::from_secs(8));
            if before(deadline, sleep(delay)).await.is_none() {
                return Err(timed_out());
            }
        }
    }
}

/// How a registration attempt for one period ended.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    /// The nullifier is registered, now or before.
    Registered,
    /// The period has no capacity left.
    CapacityExhausted,
}

/// The periods to register for, in order: the next one while it is active, then the current one
/// (WIP-107 §4.6).
fn candidate_periods(active: ActivePeriods) -> Vec<u64> {
    active.next.into_iter().chain([active.current]).collect()
}

/// The credential that proves the registration: the one the request asks for. WIP-107 accepts any
/// valid credential, but the Proof of Embedding Similarity needs this one, and the registration's
/// `issuerSchemaId` is public, so registering with another one would spend the RP's capacity for a
/// proof that fails and disclose a credential the RP did not ask about.
fn registration_credential(
    credentials: Vec<CredentialInput>,
    requested_issuer_schema_id: Option<u64>,
) -> Result<CredentialInput, WalletKitError> {
    credentials
        .into_iter()
        .find(|input| {
            Some(input.credential.issuer_schema_id) == requested_issuer_schema_id
        })
        .ok_or(WalletKitError::UnfulfillableRequest)
}

/// Reads a rejected submission: the gateway checks registration and simulates it before sending.
fn submission_outcome(error: AuthenticatorError) -> Result<Outcome, WalletKitError> {
    let code = match &error {
        AuthenticatorError::GatewayError { body, .. } => {
            serde_json::from_str::<ServiceApiError<GatewayErrorCode>>(body)
                .ok()
                .map(|error| error.code)
        }
        _ => None,
    };
    match code {
        Some(GatewayErrorCode::BillingNullifierAlreadyRegistered) => {
            Ok(Outcome::Registered)
        }
        Some(GatewayErrorCode::BillingCapacityExhausted) => {
            Ok(Outcome::CapacityExhausted)
        }
        _ => Err(error.into()),
    }
}

/// Reads a polled status: `None` while the registration is still pending.
fn status_outcome(
    state: GatewayRequestState,
) -> Result<Option<Outcome>, WalletKitError> {
    match state {
        GatewayRequestState::Queued
        | GatewayRequestState::Batching
        | GatewayRequestState::Submitted { .. } => Ok(None),
        GatewayRequestState::Finalized { .. } => Ok(Some(Outcome::Registered)),
        GatewayRequestState::Failed { error_code, error } => match error_code {
            Some(GatewayErrorCode::BillingNullifierAlreadyRegistered) => {
                Ok(Some(Outcome::Registered))
            }
            Some(GatewayErrorCode::BillingCapacityExhausted) => {
                Ok(Some(Outcome::CapacityExhausted))
            }
            _ => Err(WalletKitError::NetworkError {
                url: "gateway".to_string(),
                error: format!("billing registration failed: {error}"),
                status: None,
            }),
        },
    }
}

#[cfg(test)]
mod tests {
    use reqwest::StatusCode;
    use world_id_core::{
        api_types::{GatewayErrorCode, GatewayRequestState},
        primitives::billing::ActivePeriods,
        AuthenticatorError, Credential as CoreCredential, CredentialInput,
        FieldElement,
    };

    use super::{
        candidate_periods, registration_credential, status_outcome, submission_outcome,
        Outcome,
    };
    use crate::error::WalletKitError;

    fn gateway_error(code: &str) -> AuthenticatorError {
        AuthenticatorError::GatewayError {
            status: StatusCode::BAD_REQUEST,
            body: serde_json::json!({ "code": code, "message": "msg" }).to_string(),
        }
    }

    #[test]
    fn tries_the_next_period_before_the_current_one() {
        let overlap = ActivePeriods {
            current: 100,
            next: Some(200),
        };
        assert_eq!(candidate_periods(overlap), [200, 100]);
        let mid_month = ActivePeriods {
            current: 100,
            next: None,
        };
        assert_eq!(candidate_periods(mid_month), [100]);
    }

    fn credential(issuer_schema_id: u64) -> CredentialInput {
        CredentialInput {
            credential: CoreCredential::new().issuer_schema_id(issuer_schema_id),
            blinding_factor: FieldElement::ZERO,
        }
    }

    fn chosen(credentials: &[u64], requested: Option<u64>) -> u64 {
        registration_credential(
            credentials.iter().copied().map(credential).collect(),
            requested,
        )
        .unwrap()
        .credential
        .issuer_schema_id
    }

    #[test]
    fn registers_only_with_the_requested_credential() {
        assert_eq!(chosen(&[1, 2, 3], Some(2)), 2);
        for (credentials, requested) in [
            (vec![1, 2, 3], Some(9)),
            (vec![1, 2, 3], None),
            (Vec::new(), Some(1)),
        ] {
            assert!(matches!(
                registration_credential(
                    credentials.into_iter().map(credential).collect(),
                    requested
                ),
                Err(WalletKitError::UnfulfillableRequest)
            ));
        }
    }

    #[test]
    fn reads_rejected_submissions() {
        assert_eq!(
            submission_outcome(gateway_error("billing_nullifier_already_registered"))
                .unwrap(),
            Outcome::Registered
        );
        assert_eq!(
            submission_outcome(gateway_error("billing_capacity_exhausted")).unwrap(),
            Outcome::CapacityExhausted
        );
        for error in [
            gateway_error("bad_request"),
            AuthenticatorError::GatewayError {
                status: StatusCode::BAD_GATEWAY,
                body: "not json".to_string(),
            },
            AuthenticatorError::Generic("offline".to_string()),
        ] {
            assert!(submission_outcome(error).is_err());
        }
    }

    #[test]
    fn reads_polled_statuses() {
        for pending in [
            GatewayRequestState::Queued,
            GatewayRequestState::Batching,
            GatewayRequestState::Submitted {
                tx_hash: "0x1".to_string(),
            },
        ] {
            assert_eq!(status_outcome(pending).unwrap(), None);
        }
        assert_eq!(
            status_outcome(GatewayRequestState::Finalized {
                tx_hash: "0x1".to_string()
            })
            .unwrap(),
            Some(Outcome::Registered)
        );
        assert_eq!(
            status_outcome(GatewayRequestState::failed_from_code(
                GatewayErrorCode::BillingCapacityExhausted
            ))
            .unwrap(),
            Some(Outcome::CapacityExhausted)
        );
        assert!(matches!(
            status_outcome(GatewayRequestState::failed_from_code(
                GatewayErrorCode::TransactionReverted
            )),
            Err(WalletKitError::NetworkError { .. })
        ));
    }
}
