//! Pre-flight check of whether the credential store can satisfy a [`ProofRequest`].
//!
//! # Overview
//!
//! [`check_credentials_against_proof_request`] evaluates every request item in
//! a proof request against the contents of the local [`CredentialStore`] and returns
//! a [`CredentialConstraintsCheckResult`] describing:
//!
//! - **`is_satisfied`** — whether the overall request (including any constraint
//!   expression) can be fulfilled with the credentials currently in the store.
//! - **`check_results`** — one [`CredentialConstraintsCheckItem`] per request item,
//!   always populated regardless of `is_satisfied`, so the caller can identify
//!   exactly which credentials are present or missing.
//!
//! # Per-item evaluation
//!
//! For each request item the check verifies that the store contains at least one
//! credential that is:
//!
//! 1. **Not expired** — `expires_at > now`.
//! 2. **Fresh enough** — `genesis_issued_at >= genesis_issued_at_min` (defaults to 0
//!    when the request item omits the field, meaning any issuance time is accepted).
//! 3. **Long-lived enough** — `expires_at >= expires_at_min` (defaults to
//!    [`ProofRequest::created_at`] when the request item omits the field).
//!
//! Multiple credentials with the same `issuer_schema_id` can exist in the store.
//! The item is considered satisfied if **any** of them passes all three checks,
//! which matches proof-generation behaviour (it selects the most recently updated
//! qualifying credential).
//!
//! # Constraint expressions
//!
//! When the proof request carries a constraint expression (`Any`, `All`, or
//! `Enumerate`), `is_satisfied` reflects whether the expression evaluates to `true`
//! given the per-item results. The expression is validated for structural limits
//! (max depth 2, max [`MAX_CONSTRAINT_NODES`] nodes) before evaluation; violations
//! are returned as errors rather than `is_satisfied = false`.
//!
//! When there is no constraint expression every request item must be satisfied.
//!
//! # UI usage
//!
//! `check_results` is intended for the UI layer. When `is_satisfied` is `false`,
//! iterate `check_results` and surface items where `has_credential` is `false` to
//! tell the user which credentials are missing or do not meet the request's time
//! constraints.

use std::collections::HashMap;

use world_id_core::requests::MAX_CONSTRAINT_NODES;

use crate::requests::ProofRequest;
use crate::storage::{CredentialRecord, CredentialStore, StorageError};

/// Error returned by [`check_credentials_against_proof_request`].
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

/// Result of [`check_credentials_against_proof_request`].
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

/// Checks whether `store` holds the credentials required to fulfill `request`.
///
/// See the [module-level documentation](self) for a full description of the
/// evaluation logic and intended usage.
///
/// # Errors
///
/// - [`CredentialConstraintsCheckError::Storage`] if the credential store query fails.
/// - [`CredentialConstraintsCheckError::ConstraintTooDeep`] if the constraint tree exceeds depth 2.
/// - [`CredentialConstraintsCheckError::ConstraintTooLarge`] if the constraint tree exceeds the node limit.
#[uniffi::export]
pub fn check_credentials_against_proof_request(
    request: &ProofRequest,
    store: &CredentialStore,
    now: u64,
) -> Result<CredentialConstraintsCheckResult, CredentialConstraintsCheckError> {
    let records = store.list_credentials(None, now)?;

    let mut by_schema: HashMap<u64, Vec<&CredentialRecord>> = HashMap::new();
    for r in records.iter().filter(|r| !r.is_expired) {
        by_schema.entry(r.issuer_schema_id).or_default().push(r);
    }

    let mut check_results: Vec<CredentialConstraintsCheckItem> = Vec::new();
    for item in &request.0.requests {
        let expires_min = item.expires_at_min.unwrap_or(request.0.created_at);
        let genesis_min = item.genesis_issued_at_min.unwrap_or(0);

        let has_credential =
            by_schema.get(&item.issuer_schema_id).is_some_and(|creds| {
                creds.iter().any(|r| {
                    r.expires_at > expires_min && r.genesis_issued_at >= genesis_min
                })
            });

        check_results.push(CredentialConstraintsCheckItem {
            identifier: item.identifier.clone(),
            issuer_schema_id: item.issuer_schema_id,
            has_credential,
        });
    }

    let is_satisfied = match &request.0.constraints {
        None => check_results.iter().all(|i| i.has_credential),
        Some(expr) => {
            // TODO: replace with `request.0.validate_constraints()?` once
            // walletkit bumps world-id-core to 0.11.x.
            if !expr.validate_max_depth(2) {
                return Err(CredentialConstraintsCheckError::ConstraintTooDeep);
            }
            if !expr.validate_max_nodes(MAX_CONSTRAINT_NODES) {
                return Err(CredentialConstraintsCheckError::ConstraintTooLarge);
            }
            expr.evaluate(&|id: &str| {
                check_results
                    .iter()
                    .any(|i| i.identifier == id && i.has_credential)
            })
        }
    };

    Ok(CredentialConstraintsCheckResult {
        is_satisfied,
        check_results,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use alloy_core::primitives::{Signature, U160};
    use taceo_oprf::types::OprfKeyId;
    use world_id_core::{
        primitives::rp::RpId,
        requests::{
            ConstraintExpr, ConstraintNode, ProofRequest as CoreProofRequest,
            RequestItem, RequestVersion,
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

    fn dummy_request(
        items: Vec<RequestItem>,
        constraints: Option<ConstraintExpr<'static>>,
    ) -> ProofRequest {
        let core = CoreProofRequest {
            id: "test".to_string(),
            version: RequestVersion::V1,
            created_at: 0,
            expires_at: u64::MAX,
            rp_id: RpId::new(1),
            oprf_key_id: OprfKeyId::new(U160::from(1u64)),
            session_id: None,
            action: None,
            signature: Signature::test_signature(),
            nonce: CoreFieldElement::ZERO,
            requests: items,
            constraints,
        };
        ProofRequest(core)
    }

    fn store_with_credentials(
        issuer_ids: &[u64],
        now: u64,
    ) -> (CredentialStore, std::path::PathBuf) {
        let root = temp_root_path();
        let provider = InMemoryStorageProvider::new(&root);
        let store = CredentialStore::from_provider(&provider).expect("create store");
        store.init(42, now).expect("init");

        for &id in issuer_ids {
            let cred: Credential = CoreCredential::new()
                .issuer_schema_id(id)
                .genesis_issued_at(now)
                .into();
            store
                .store_credential(
                    &cred,
                    &FieldElement::from(1u64),
                    now + 9999,
                    None,
                    now,
                )
                .expect("store credential");
        }
        (store, root)
    }

    #[test]
    fn no_constraints_all_satisfied() {
        let now = 1000;
        let (store, root) = store_with_credentials(&[100, 200], now);
        let request = dummy_request(
            vec![
                RequestItem::new("a".into(), 100, None, None, None),
                RequestItem::new("b".into(), 200, None, None, None),
            ],
            None,
        );
        let result =
            check_credentials_against_proof_request(&request, &store, now).unwrap();
        assert!(result.is_satisfied);
        assert!(result.check_results.iter().all(|i| i.has_credential));
        cleanup_test_storage(&root);
    }

    #[test]
    fn no_constraints_one_missing() {
        let now = 1000;
        let (store, root) = store_with_credentials(&[100], now);
        let request = dummy_request(
            vec![
                RequestItem::new("a".into(), 100, None, None, None),
                RequestItem::new("b".into(), 999, None, None, None),
            ],
            None,
        );
        let result =
            check_credentials_against_proof_request(&request, &store, now).unwrap();
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
        let root = temp_root_path();
        let provider = InMemoryStorageProvider::new(&root);
        let store = CredentialStore::from_provider(&provider).expect("create store");
        store.init(42, 1000).expect("init");

        let cred: Credential = CoreCredential::new()
            .issuer_schema_id(100)
            .genesis_issued_at(1000)
            .into();
        store
            .store_credential(&cred, &FieldElement::from(1u64), 2000, None, 1000)
            .expect("store");

        let request = dummy_request(
            vec![RequestItem::new("a".into(), 100, None, None, None)],
            None,
        );

        let result =
            check_credentials_against_proof_request(&request, &store, now).unwrap();
        assert!(!result.is_satisfied);
        assert!(!result.check_results[0].has_credential);
        cleanup_test_storage(&root);
    }

    #[test]
    fn any_constraint_one_branch_satisfied() {
        let now = 1000;
        let (store, root) = store_with_credentials(&[100], now);
        let request = dummy_request(
            vec![
                RequestItem::new("a".into(), 100, None, None, None),
                RequestItem::new("b".into(), 999, None, None, None),
            ],
            Some(ConstraintExpr::Any {
                any: vec![
                    ConstraintNode::Type("a".into()),
                    ConstraintNode::Type("b".into()),
                ],
            }),
        );
        assert!(
            check_credentials_against_proof_request(&request, &store, now)
                .unwrap()
                .is_satisfied
        );
        cleanup_test_storage(&root);
    }

    #[test]
    fn all_constraint_one_branch_missing() {
        let now = 1000;
        let (store, root) = store_with_credentials(&[100], now);
        let request = dummy_request(
            vec![
                RequestItem::new("a".into(), 100, None, None, None),
                RequestItem::new("b".into(), 999, None, None, None),
            ],
            Some(ConstraintExpr::All {
                all: vec![
                    ConstraintNode::Type("a".into()),
                    ConstraintNode::Type("b".into()),
                ],
            }),
        );
        let result =
            check_credentials_against_proof_request(&request, &store, now).unwrap();
        assert!(!result.is_satisfied);
        assert!(result.check_results[0].has_credential);
        assert!(!result.check_results[1].has_credential);
        cleanup_test_storage(&root);
    }

    #[test]
    fn enumerate_constraint_any_branch_satisfies() {
        let now = 1000;
        let (store, root) = store_with_credentials(&[200], now);
        let request = dummy_request(
            vec![
                RequestItem::new("a".into(), 999, None, None, None),
                RequestItem::new("b".into(), 200, None, None, None),
            ],
            Some(ConstraintExpr::Enumerate {
                enumerate: vec![
                    ConstraintNode::Type("a".into()),
                    ConstraintNode::Type("b".into()),
                ],
            }),
        );
        assert!(
            check_credentials_against_proof_request(&request, &store, now)
                .unwrap()
                .is_satisfied
        );
        cleanup_test_storage(&root);
    }

    #[test]
    fn enumerate_constraint_none_available() {
        let now = 1000;
        let (store, root) = store_with_credentials(&[], now);
        let request = dummy_request(
            vec![
                RequestItem::new("a".into(), 100, None, None, None),
                RequestItem::new("b".into(), 200, None, None, None),
            ],
            Some(ConstraintExpr::Enumerate {
                enumerate: vec![
                    ConstraintNode::Type("a".into()),
                    ConstraintNode::Type("b".into()),
                ],
            }),
        );
        assert!(
            !check_credentials_against_proof_request(&request, &store, now)
                .unwrap()
                .is_satisfied
        );
        cleanup_test_storage(&root);
    }

    // -----------------------------------------------------------------------
    // Table cases: A or B or C / A and (B or C)
    // -----------------------------------------------------------------------

    fn three_item_request(constraints: ConstraintExpr<'static>) -> ProofRequest {
        dummy_request(
            vec![
                RequestItem::new("a".into(), 100, None, None, None),
                RequestItem::new("b".into(), 200, None, None, None),
                RequestItem::new("c".into(), 300, None, None, None),
            ],
            Some(constraints),
        )
    }

    fn any_a_or_b_or_c() -> ConstraintExpr<'static> {
        ConstraintExpr::Any {
            any: vec![
                ConstraintNode::Type("a".into()),
                ConstraintNode::Type("b".into()),
                ConstraintNode::Type("c".into()),
            ],
        }
    }

    fn all_a_and_b_or_c() -> ConstraintExpr<'static> {
        ConstraintExpr::All {
            all: vec![
                ConstraintNode::Type("a".into()),
                ConstraintNode::Expr(ConstraintExpr::Any {
                    any: vec![
                        ConstraintNode::Type("b".into()),
                        ConstraintNode::Type("c".into()),
                    ],
                }),
            ],
        }
    }

    // A or B or C — only A present → True
    #[test]
    fn any_abc_only_a_satisfies() {
        let now = 1000;
        let (store, root) = store_with_credentials(&[100], now);
        let result = check_credentials_against_proof_request(
            &three_item_request(any_a_or_b_or_c()),
            &store,
            now,
        )
        .unwrap();
        assert!(result.is_satisfied);
        assert!(
            result
                .check_results
                .iter()
                .find(|i| i.identifier == "a")
                .unwrap()
                .has_credential
        );
        assert!(
            !result
                .check_results
                .iter()
                .find(|i| i.identifier == "b")
                .unwrap()
                .has_credential
        );
        assert!(
            !result
                .check_results
                .iter()
                .find(|i| i.identifier == "c")
                .unwrap()
                .has_credential
        );
        cleanup_test_storage(&root);
    }

    // A or B or C — only B present → True
    #[test]
    fn any_abc_only_b_satisfies() {
        let now = 1000;
        let (store, root) = store_with_credentials(&[200], now);
        let result = check_credentials_against_proof_request(
            &three_item_request(any_a_or_b_or_c()),
            &store,
            now,
        )
        .unwrap();
        assert!(result.is_satisfied);
        assert!(
            !result
                .check_results
                .iter()
                .find(|i| i.identifier == "a")
                .unwrap()
                .has_credential
        );
        assert!(
            result
                .check_results
                .iter()
                .find(|i| i.identifier == "b")
                .unwrap()
                .has_credential
        );
        assert!(
            !result
                .check_results
                .iter()
                .find(|i| i.identifier == "c")
                .unwrap()
                .has_credential
        );
        cleanup_test_storage(&root);
    }

    // A or B or C — none present → False
    #[test]
    fn any_abc_none_present() {
        let now = 1000;
        let (store, root) = store_with_credentials(&[], now);
        let result = check_credentials_against_proof_request(
            &three_item_request(any_a_or_b_or_c()),
            &store,
            now,
        )
        .unwrap();
        assert!(!result.is_satisfied);
        assert!(result.check_results.iter().all(|i| !i.has_credential));
        cleanup_test_storage(&root);
    }

    // A and (B or C) — none present → False
    #[test]
    fn all_a_any_bc_none_present() {
        let now = 1000;
        let (store, root) = store_with_credentials(&[], now);
        let result = check_credentials_against_proof_request(
            &three_item_request(all_a_and_b_or_c()),
            &store,
            now,
        )
        .unwrap();
        assert!(!result.is_satisfied);
        cleanup_test_storage(&root);
    }

    // A and (B or C) — A, B, C all present → True (A satisfies A; B satisfies B or C)
    #[test]
    fn all_a_any_bc_all_present() {
        let now = 1000;
        let (store, root) = store_with_credentials(&[100, 200, 300], now);
        let result = check_credentials_against_proof_request(
            &three_item_request(all_a_and_b_or_c()),
            &store,
            now,
        )
        .unwrap();
        assert!(result.is_satisfied);
        assert!(result.check_results.iter().all(|i| i.has_credential));
        cleanup_test_storage(&root);
    }

    #[test]
    fn constraint_too_deep_returns_error() {
        let now = 1000;
        let (store, root) = store_with_credentials(&[100], now);
        let deep = ConstraintExpr::All {
            all: vec![ConstraintNode::Expr(ConstraintExpr::Any {
                any: vec![ConstraintNode::Expr(ConstraintExpr::All {
                    all: vec![ConstraintNode::Type("a".into())],
                })],
            })],
        };
        let request = dummy_request(
            vec![RequestItem::new("a".into(), 100, None, None, None)],
            Some(deep),
        );
        let err =
            check_credentials_against_proof_request(&request, &store, now).unwrap_err();
        assert!(matches!(
            err,
            CredentialConstraintsCheckError::ConstraintTooDeep
        ));
        cleanup_test_storage(&root);
    }

    #[test]
    fn constraint_too_large_returns_error() {
        use world_id_core::requests::MAX_CONSTRAINT_NODES;
        let now = 1000;
        let (store, root) = store_with_credentials(&[], now);
        // Build a flat Any with MAX_CONSTRAINT_NODES + 1 leaves to exceed the limit.
        let nodes: Vec<ConstraintNode<'static>> = (0..=MAX_CONSTRAINT_NODES)
            .map(|i| ConstraintNode::Type(format!("t{i}").into()))
            .collect();
        let expr = ConstraintExpr::Any { any: nodes };
        let items: Vec<RequestItem> = (0..=MAX_CONSTRAINT_NODES)
            .map(|i| RequestItem::new(format!("t{i}"), i as u64, None, None, None))
            .collect();
        let request = dummy_request(items, Some(expr));
        let err =
            check_credentials_against_proof_request(&request, &store, now).unwrap_err();
        assert!(matches!(
            err,
            CredentialConstraintsCheckError::ConstraintTooLarge
        ));
        cleanup_test_storage(&root);
    }

    fn store_with_credential_times(
        issuer_id: u64,
        genesis_issued_at: u64,
        expires_at: u64,
        now: u64,
    ) -> (CredentialStore, std::path::PathBuf) {
        let root = temp_root_path();
        let provider = InMemoryStorageProvider::new(&root);
        let store = CredentialStore::from_provider(&provider).expect("create store");
        store.init(42, now).expect("init");
        let cred: Credential = CoreCredential::new()
            .issuer_schema_id(issuer_id)
            .genesis_issued_at(genesis_issued_at)
            .into();
        store
            .store_credential(&cred, &FieldElement::from(1u64), expires_at, None, now)
            .expect("store credential");
        (store, root)
    }

    #[test]
    fn genesis_issued_at_min_not_met_returns_unsatisfied() {
        let now = 1000;
        // Credential was issued at t=500; request requires t>=600.
        let (store, root) = store_with_credential_times(100, 500, now + 9999, now);
        let request = dummy_request(
            vec![RequestItem::new("a".into(), 100, None, Some(600), None)],
            None,
        );
        let result =
            check_credentials_against_proof_request(&request, &store, now).unwrap();
        assert!(!result.is_satisfied);
        assert!(!result.check_results[0].has_credential);
        cleanup_test_storage(&root);
    }

    #[test]
    fn expires_at_min_not_met_returns_unsatisfied() {
        let now = 1000;
        // Credential expires at t=2000; request requires expires_at >= 5000.
        let (store, root) = store_with_credential_times(100, now, 2000, now);
        let request = dummy_request(
            vec![RequestItem::new("a".into(), 100, None, None, Some(5000))],
            None,
        );
        let result =
            check_credentials_against_proof_request(&request, &store, now).unwrap();
        assert!(!result.is_satisfied);
        assert!(!result.check_results[0].has_credential);
        cleanup_test_storage(&root);
    }

    #[test]
    fn expires_at_min_equal_to_expires_at_returns_unsatisfied() {
        let now = 1000;
        // Boundary: expires_at == expires_at_min is rejected by the circuit (strict >).
        let (store, root) = store_with_credential_times(100, now, 5000, now);
        let request = dummy_request(
            vec![RequestItem::new("a".into(), 100, None, None, Some(5000))],
            None,
        );
        let result =
            check_credentials_against_proof_request(&request, &store, now).unwrap();
        assert!(!result.is_satisfied);
        assert!(!result.check_results[0].has_credential);
        cleanup_test_storage(&root);
    }
}
