//! Pre-flight check of whether the credential store can satisfy a proof request.
//!
//! Call [`ProofRequest::check_credentials`] to evaluate a request against the local
//! credential store before attempting proof generation. See [`ProofRequest`] docs for
//! constraint semantics.

use std::collections::HashSet;

use itertools::Itertools;
use world_id_core::requests::ValidationError;

use crate::requests::ProofRequest;
use crate::storage::{CredentialStore, StorageError};

/// Error returned by [`ProofRequest::check_credentials`].
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum CredentialConstraintsCheckError {
    /// Credential store query failed.
    #[error(transparent)]
    Storage(#[from] StorageError),
    /// The constraint expression exceeds the maximum nesting depth of 2.
    #[error("constraint nesting exceeds maximum allowed depth")]
    ConstraintTooDeep,
    /// The constraint expression exceeds the maximum node count.
    #[error("constraints exceed maximum allowed size")]
    ConstraintTooLarge,
    /// An unexpected validation error was returned by the upstream crate.
    #[error("unexpected validation error: {0}")]
    Unknown(String),
}

impl From<ValidationError> for CredentialConstraintsCheckError {
    fn from(e: ValidationError) -> Self {
        match e {
            ValidationError::ConstraintTooDeep => Self::ConstraintTooDeep,
            ValidationError::ConstraintTooLarge => Self::ConstraintTooLarge,
            other => Self::Unknown(format!("{other:?}")),
        }
    }
}

/// Check result for a single request item.
#[derive(Debug, Clone, uniffi::Record)]
pub struct CredentialConstraintsCheckItem {
    /// The RP-defined identifier for this request item (e.g. `"orb"`, `"document"`).
    pub identifier: String,
    /// Issuer schema ID required by this item.
    pub issuer_schema_id: u64,
    /// `true` when the store contains at least one non-expired credential that meets
    /// all time constraints (`genesis_issued_at_min`, `expires_at_min`) for this item.
    pub has_credential: bool,
}

/// Result of [`ProofRequest::check_credentials`].
#[derive(Debug, Clone, uniffi::Record)]
pub struct CredentialConstraintsCheckResult {
    /// `true` when the constraint tree (or all items, if no constraints) is satisfied.
    pub is_satisfied: bool,
    /// One entry per request item in the proof request, in the same order.
    ///
    /// Always populated regardless of `is_satisfied`. When `is_satisfied` is `false`,
    /// items with `has_credential = false` identify what is missing or does not meet
    /// the request's time constraints.
    pub check_results: Vec<CredentialConstraintsCheckItem>,
}

#[uniffi::export]
impl ProofRequest {
    /// Checks whether `store` holds the credentials required to fulfill this request.
    ///
    /// For each request item the check verifies that the store contains at least one
    /// credential that is not expired and meets `genesis_issued_at_min` and
    /// `expires_at_min`. When the request carries a constraint expression, `is_satisfied`
    /// reflects whether that expression evaluates to `true` given the per-item results.
    ///
    /// # Errors
    ///
    /// - [`CredentialConstraintsCheckError::Storage`] if the credential store query fails.
    /// - [`CredentialConstraintsCheckError::ConstraintTooDeep`] if the constraint tree exceeds depth 2.
    /// - [`CredentialConstraintsCheckError::ConstraintTooLarge`] if the constraint tree exceeds the node limit.
    pub fn check_credentials(
        &self,
        store: &CredentialStore,
        now: u64,
    ) -> Result<CredentialConstraintsCheckResult, CredentialConstraintsCheckError> {
        self.0.validate_constraints()?;

        let records = store.list_credentials(None, now)?;

        let by_schema = records
            .into_iter()
            .filter(|r| !r.is_expired)
            .into_group_map_by(|r| r.issuer_schema_id);

        let check_results = self
            .0
            .requests
            .iter()
            .map(|item| {
                let expires_min = item.effective_expires_at_min(self.0.created_at);
                let genesis_min = item.genesis_issued_at_min.unwrap_or(0);

                let has_credential =
                    by_schema.get(&item.issuer_schema_id).is_some_and(|creds| {
                        creds.iter().any(|r| {
                            r.expires_at > expires_min
                                && r.genesis_issued_at >= genesis_min
                        })
                    });

                CredentialConstraintsCheckItem {
                    identifier: item.identifier.clone(),
                    issuer_schema_id: item.issuer_schema_id,
                    has_credential,
                }
            })
            .collect::<Vec<_>>();

        let available_credentials = check_results
            .iter()
            .filter_map(|r| r.has_credential.then_some(r.issuer_schema_id))
            .collect::<HashSet<_>>();

        let is_satisfied = self
            .0
            .credentials_to_prove(&available_credentials)
            .is_some();

        Ok(CredentialConstraintsCheckResult {
            is_satisfied,
            check_results,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use alloy_core::primitives::{Signature, U160};
    use taceo_oprf::types::OprfKeyId;
    use world_id_core::{
        primitives::rp::RpId,
        requests::{
            ProofRequest as CoreProofRequest, ProofType, RequestItem, RequestVersion,
        },
        FieldElement as CoreFieldElement,
    };

    use crate::{
        storage::tests_utils::{
            cleanup_test_storage, temp_root_path, InMemoryStorageProvider,
        },
        Credential, FieldElement,
    };
    use world_id_core::Credential as CoreCredential;

    fn dummy_request(items: Vec<RequestItem>) -> ProofRequest {
        let core = CoreProofRequest {
            id: "test".to_string(),
            version: RequestVersion::V1,
            created_at: 0,
            expires_at: u64::MAX,
            rp_id: RpId::new(1),
            oprf_key_id: OprfKeyId::new(U160::from(1u64)),
            proof_type: ProofType::default(),
            session_id: None,
            action: None,
            signature: Signature::test_signature(),
            nonce: CoreFieldElement::ZERO,
            requests: items,
            constraints: None,
        };
        ProofRequest(core)
    }

    /// Creates a test store populated with one credential per entry in `issuer_ids`.
    /// `genesis_issued_at` defaults to `init_time`; `expires_at` defaults to `init_time + 9999`.
    #[bon::builder]
    fn make_store(
        issuer_ids: Vec<u64>,
        init_time: u64,
        genesis_issued_at: Option<u64>,
        expires_at: Option<u64>,
    ) -> (CredentialStore, std::path::PathBuf) {
        let genesis_issued_at = genesis_issued_at.unwrap_or(init_time);
        let expires_at = expires_at.unwrap_or(init_time + 9999);

        let root = temp_root_path();
        let provider = InMemoryStorageProvider::new(&root);
        let store = CredentialStore::from_provider(&provider).expect("create store");
        store.init(42, init_time).expect("init");

        for id in issuer_ids {
            let cred: Credential = CoreCredential::new()
                .issuer_schema_id(id)
                .genesis_issued_at(genesis_issued_at)
                .into();
            store
                .store_credential(
                    &cred,
                    &FieldElement::from(1u64),
                    expires_at,
                    None,
                    init_time,
                )
                .expect("store credential");
        }
        (store, root)
    }

    #[test]
    fn no_constraints_all_satisfied() {
        let now = 1000;
        let (store, root) = make_store()
            .issuer_ids(vec![100, 200])
            .init_time(now)
            .call();
        let request = dummy_request(vec![
            RequestItem::new("a".into(), 100, None, None, None),
            RequestItem::new("b".into(), 200, None, None, None),
        ]);
        let result = request.check_credentials(&store, now).unwrap();
        assert!(result.is_satisfied);
        assert!(result.check_results.iter().all(|i| i.has_credential));
        cleanup_test_storage(&root);
    }

    #[test]
    fn no_constraints_one_missing() {
        let now = 1000;
        let (store, root) = make_store().issuer_ids(vec![100]).init_time(now).call();
        let request = dummy_request(vec![
            RequestItem::new("a".into(), 100, None, None, None),
            RequestItem::new("b".into(), 999, None, None, None),
        ]);
        let result = request.check_credentials(&store, now).unwrap();
        assert!(!result.is_satisfied);
        assert!(result.check_results[0].has_credential);
        assert!(!result.check_results[1].has_credential);
        assert_eq!(result.check_results[1].identifier, "b");
        assert_eq!(result.check_results[1].issuer_schema_id, 999);
        cleanup_test_storage(&root);
    }

    #[test]
    fn expired_credential_not_counted() {
        let now = 5000;
        let (store, root) = make_store()
            .issuer_ids(vec![100])
            .init_time(1000)
            .expires_at(2000)
            .call();

        let request =
            dummy_request(vec![RequestItem::new("a".into(), 100, None, None, None)]);

        let result = request.check_credentials(&store, now).unwrap();
        assert!(!result.is_satisfied);
        assert!(!result.check_results[0].has_credential);
        cleanup_test_storage(&root);
    }

    #[test]
    fn genesis_issued_at_min_not_met_returns_unsatisfied() {
        let now = 1000;
        let (store, root) = make_store()
            .issuer_ids(vec![100])
            .init_time(now)
            .genesis_issued_at(500)
            .call();
        let request = dummy_request(vec![RequestItem::new(
            "a".into(),
            100,
            None,
            Some(600),
            None,
        )]);
        let result = request.check_credentials(&store, now).unwrap();
        assert!(!result.is_satisfied);
        assert!(!result.check_results[0].has_credential);
        cleanup_test_storage(&root);
    }

    #[test]
    fn expires_at_min_not_met_returns_unsatisfied() {
        let now = 1000;
        let (store, root) = make_store()
            .issuer_ids(vec![100])
            .init_time(now)
            .expires_at(2000)
            .call();
        let request = dummy_request(vec![RequestItem::new(
            "a".into(),
            100,
            None,
            None,
            Some(5000),
        )]);
        let result = request.check_credentials(&store, now).unwrap();
        assert!(!result.is_satisfied);
        assert!(!result.check_results[0].has_credential);
        cleanup_test_storage(&root);
    }

    #[test]
    fn expires_at_min_equal_to_expires_at_returns_unsatisfied() {
        let now = 1000;
        // Boundary: expires_at == expires_at_min is rejected by the circuit (strict >).
        let (store, root) = make_store()
            .issuer_ids(vec![100])
            .init_time(now)
            .expires_at(5000)
            .call();
        let request = dummy_request(vec![RequestItem::new(
            "a".into(),
            100,
            None,
            None,
            Some(5000),
        )]);
        let result = request.check_credentials(&store, now).unwrap();
        assert!(!result.is_satisfied);
        assert!(!result.check_results[0].has_credential);
        cleanup_test_storage(&root);
    }
}
