//! Selection of the stored credentials that answer a proof request.
//!
//! A proof request lists credentials and, optionally, a constraint expression
//! (`all`, `any`, `enumerate`) over them, so several sets of stored credentials
//! can satisfy the same request. [`CredentialStore::select_credentials`] picks
//! one of them, and [`Authenticator::generate_proof`] proves exactly the set the
//! same query picks. The app can therefore inspect a selection, act on it (for
//! example, compare the user's face against one of the selected credentials),
//! and then prove that selection by pinning it.
//!
//! [`Authenticator::generate_proof`]: crate::Authenticator::generate_proof
//!
//! # Order
//!
//! Selections are tried in the relying party's order:
//!
//! - `any` tries its children in the listed order;
//! - `all` takes one selection from every child, varying the last child first;
//! - `enumerate` takes one selection from every child that can be satisfied;
//! - without constraints, every request item is required.
//!
//! With an allow-all [`CredentialFilter`] the first selection is the one
//! `world-id-core` would pick. The constraint expression is limited in depth
//! and size, so the number of selections is small.
//!
//! # Filtering
//!
//! A [`CredentialFilter`] narrows the query at two levels:
//!
//! - Per credential: a request item is answered by the most recent stored
//!   credential for its issuer schema that is not expired, meets the item's
//!   `genesis_issued_at_min` and `expires_at_min`, and passes the filter.
//! - Per selection: the first selection in order whose credential IDs pass the
//!   filter is returned.
//!
//! | Request                    | Usable credentials | Filter                     | Selection    |
//! |----------------------------|--------------------|----------------------------|--------------|
//! | `any(passport, orb)`       | passport, orb      | allow all                  | passport     |
//! | `any(passport, orb)`       | passport, orb      | requiring any of `{orb}`   | orb          |
//! | `any(passport, orb)`       | passport, orb      | excluding `{passport}`     | orb          |
//! | `all(device, any(a, orb))` | device, a, orb     | requiring any of `{orb}`   | device, orb  |
//! | `any(passport, orb)`       | passport           | requiring any of `{orb}`   | _(error)_    |

use std::collections::{BTreeSet, HashMap, HashSet};

use world_id_core::requests::{
    ConstraintExpr, ConstraintNode, ProofRequest as CoreProofRequest, RequestItem,
};

use crate::error::WalletKitError;
use crate::requests::ProofRequest;
use crate::storage::{CredentialRecord, CredentialStore};

/// Restricts which stored credentials a proof request is answered with.
///
/// Build one with [`CredentialFilter::new`], which allows every credential,
/// and narrow it with the builder methods. Each method returns a new filter and
/// replaces the value previously set by the same method. All restrictions
/// apply together.
#[derive(Debug, Clone, Default, PartialEq, Eq, uniffi::Object)]
pub struct CredentialFilter {
    /// Credential IDs that never answer a request item.
    excluded: BTreeSet<u64>,
    /// Credential IDs of which an accepted selection contains at least one.
    required: Option<BTreeSet<u64>>,
    /// Credential IDs an accepted selection consists of exactly.
    pinned: Option<BTreeSet<u64>>,
}

#[uniffi::export]
impl CredentialFilter {
    /// Creates a filter that allows every credential.
    #[uniffi::constructor]
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Never answers a request with these credentials.
    ///
    /// An excluded credential's issuer schema is answered by its next most
    /// recent usable credential, if any.
    #[must_use]
    pub fn excluding_credential_ids(&self, credential_ids: HashSet<u64>) -> Self {
        Self {
            excluded: credential_ids.into_iter().collect(),
            ..self.clone()
        }
    }

    /// Only accepts selections that contain at least one of these credentials.
    ///
    /// The first selection in the relying party's order that contains one of
    /// them is used, even when an earlier selection could be proven. An empty
    /// set accepts no selection.
    #[must_use]
    pub fn requiring_any_of(&self, credential_ids: HashSet<u64>) -> Self {
        Self {
            required: Some(credential_ids.into_iter().collect()),
            ..self.clone()
        }
    }

    /// Only accepts a selection made of exactly these credentials.
    ///
    /// Use it to prove a selection previously returned by
    /// [`CredentialStore::select_credentials`]: the pinned credentials are used
    /// even if newer versions were stored since, and the request fails instead
    /// of proving a different set if they no longer answer it. An empty set
    /// accepts no selection.
    #[must_use]
    pub fn pinned_to(&self, credential_ids: HashSet<u64>) -> Self {
        Self {
            pinned: Some(credential_ids.into_iter().collect()),
            ..self.clone()
        }
    }
}

impl CredentialFilter {
    fn allows_credential(&self, credential_id: u64) -> bool {
        !self.excluded.contains(&credential_id)
            && self
                .pinned
                .as_ref()
                .is_none_or(|pinned| pinned.contains(&credential_id))
    }

    fn accepts_selection(&self, credential_ids: &BTreeSet<u64>) -> bool {
        let has_required = self
            .required
            .as_ref()
            .is_none_or(|required| !required.is_disjoint(credential_ids));
        let matches_pin = self
            .pinned
            .as_ref()
            .is_none_or(|pinned| pinned == credential_ids);
        has_required && matches_pin
    }
}

/// A stored credential chosen to answer one item of a proof request.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SelectedCredential {
    /// The relying party's identifier of the request item, e.g. `"orb"`.
    pub identifier: String,
    /// The stored credential that answers the item.
    pub credential_id: u64,
    /// Issuer schema of the credential.
    pub issuer_schema_id: u64,
    /// Genesis issuance timestamp of the credential (seconds).
    pub genesis_issued_at: u64,
    /// Expiry timestamp of the credential (seconds).
    pub expires_at: u64,
}

#[uniffi::export]
impl CredentialStore {
    /// Selects the stored credentials that answer `request`.
    ///
    /// The query is read-only: it contacts no service and records nothing, so
    /// it can run before the user confirms the request. Pass the returned
    /// credential IDs to [`CredentialFilter::pinned_to`] to prove this exact
    /// selection. See the [module documentation](self) for the selection rules.
    ///
    /// Returns one entry per selected request item, in request order.
    ///
    /// # Errors
    ///
    /// - [`WalletKitError::UnfulfillableRequest`] if no selection of usable
    ///   credentials satisfies both the request and `filter`.
    /// - [`WalletKitError::InvalidInput`] if the constraint expression exceeds
    ///   the protocol's depth or size limits.
    /// - [`WalletKitError::Generic`] if the credential store cannot be read.
    pub fn select_credentials(
        &self,
        request: &ProofRequest,
        filter: &CredentialFilter,
        now: u64,
    ) -> Result<Vec<SelectedCredential>, WalletKitError> {
        let records = self.list_credentials(None, now)?;
        select_credentials(&request.0, &records, filter)
    }
}

/// Selects which of `records` answer `request`. `records` must be ordered most
/// recent version first, as [`CredentialStore::list_credentials`] returns them.
pub(crate) fn select_credentials(
    request: &CoreProofRequest,
    records: &[CredentialRecord],
    filter: &CredentialFilter,
) -> Result<Vec<SelectedCredential>, WalletKitError> {
    request
        .validate_constraints()
        .map_err(|err| WalletKitError::InvalidInput {
            attribute: "constraints".to_string(),
            reason: err.to_string(),
        })?;

    let usable: HashMap<&str, &CredentialRecord> = request
        .requests
        .iter()
        .filter_map(|item| {
            records
                .iter()
                .find(|record| {
                    record.issuer_schema_id == item.issuer_schema_id
                        && is_usable_for(record, item, request.created_at)
                        && filter.allows_credential(record.credential_id)
                })
                .map(|record| (item.identifier.as_str(), record))
        })
        .collect();
    let is_usable = |identifier: &str| usable.contains_key(identifier);

    let selections = match &request.constraints {
        Some(expr) => expr_selections(expr, &is_usable),
        None if request
            .requests
            .iter()
            .all(|item| is_usable(&item.identifier)) =>
        {
            vec![request
                .requests
                .iter()
                .map(|item| item.identifier.as_str())
                .collect()]
        }
        None => Vec::new(),
    };

    selections
        .into_iter()
        .find(|identifiers| {
            let credential_ids = identifiers
                .iter()
                .map(|identifier| usable[identifier].credential_id)
                .collect();
            filter.accepts_selection(&credential_ids)
        })
        .map(|identifiers| {
            request
                .requests
                .iter()
                .filter(|item| identifiers.contains(item.identifier.as_str()))
                .map(|item| {
                    let record = usable[item.identifier.as_str()];
                    SelectedCredential {
                        identifier: item.identifier.clone(),
                        credential_id: record.credential_id,
                        issuer_schema_id: record.issuer_schema_id,
                        genesis_issued_at: record.genesis_issued_at,
                        expires_at: record.expires_at,
                    }
                })
                .collect()
        })
        .ok_or(WalletKitError::UnfulfillableRequest)
}

/// Whether `record` can answer `item` of a request created at
/// `request_created_at`: it is not expired and meets the item's time
/// constraints. It does not compare issuer schemas.
pub(crate) fn is_usable_for(
    record: &CredentialRecord,
    item: &RequestItem,
    request_created_at: u64,
) -> bool {
    !record.is_expired
        && record.expires_at > item.effective_expires_at_min(request_created_at)
        && record.genesis_issued_at >= item.genesis_issued_at_min.unwrap_or(0)
}

/// A set of request item identifiers that satisfies a constraint expression.
type Selection<'a> = BTreeSet<&'a str>;

/// Lists every selection that satisfies `expr`, in the relying party's order.
fn expr_selections<'a>(
    expr: &'a ConstraintExpr<'_>,
    is_usable: &impl Fn(&str) -> bool,
) -> Vec<Selection<'a>> {
    let child_selections = |children: &'a [ConstraintNode<'_>]| {
        children
            .iter()
            .map(|child| node_selections(child, is_usable))
            .collect::<Vec<_>>()
    };

    match expr {
        ConstraintExpr::All { all } => combine(child_selections(all)),
        ConstraintExpr::Any { any } => {
            child_selections(any).into_iter().flatten().collect()
        }
        ConstraintExpr::Enumerate { enumerate } => {
            let satisfiable: Vec<_> = child_selections(enumerate)
                .into_iter()
                .filter(|selections| !selections.is_empty())
                .collect();
            if satisfiable.is_empty() {
                return Vec::new();
            }
            combine(satisfiable)
        }
    }
}

fn node_selections<'a>(
    node: &'a ConstraintNode<'_>,
    is_usable: &impl Fn(&str) -> bool,
) -> Vec<Selection<'a>> {
    match node {
        ConstraintNode::Type(identifier) if is_usable(identifier) => {
            vec![BTreeSet::from([identifier.as_ref()])]
        }
        ConstraintNode::Type(_) => Vec::new(),
        ConstraintNode::Expr(expr) => expr_selections(expr, is_usable),
    }
}

/// Lists every union of one selection from each group, varying the last group
/// first. Returns no selection if any group is empty.
fn combine(groups: Vec<Vec<Selection<'_>>>) -> Vec<Selection<'_>> {
    groups
        .into_iter()
        .fold(vec![Selection::new()], |prefixes, group| {
            prefixes
                .iter()
                .flat_map(|prefix| {
                    group.iter().map(move |selection| {
                        prefix.union(selection).copied().collect()
                    })
                })
                .collect()
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    use alloy_core::primitives::{Signature, U160};
    use world_id_core::{
        primitives::{rp::RpId, OprfKeyId, SessionRef},
        requests::{ProofType, RequestVersion},
        FieldElement as CoreFieldElement,
    };

    const REQUEST_CREATED_AT: u64 = 1_000;

    const PASSPORT: u64 = 1;
    const ORB: u64 = 2;
    const DEVICE: u64 = 3;
    const SELFIE: u64 = 4;

    fn item(identifier: &str, issuer_schema_id: u64) -> RequestItem {
        RequestItem {
            identifier: identifier.to_string(),
            issuer_schema_id,
            signal: None,
            genesis_issued_at_min: None,
            expires_at_min: None,
        }
    }

    fn standard_items() -> Vec<RequestItem> {
        vec![
            item("passport", PASSPORT),
            item("orb", ORB),
            item("device", DEVICE),
            item("selfie", SELFIE),
        ]
    }

    fn request(
        requests: Vec<RequestItem>,
        constraints: Option<serde_json::Value>,
    ) -> CoreProofRequest {
        CoreProofRequest {
            id: "test".to_string(),
            version: RequestVersion::V1,
            proof_type: ProofType::Uniqueness,
            created_at: REQUEST_CREATED_AT,
            expires_at: u64::MAX,
            rp_id: RpId::new(1),
            oprf_key_id: OprfKeyId::new(U160::from(1u64)),
            session_id: SessionRef::None,
            action: None,
            signature: Signature::test_signature(),
            nonce: CoreFieldElement::ZERO,
            requests,
            constraints: constraints
                .map(|value| serde_json::from_value(value).expect("valid constraints")),
        }
    }

    fn record(credential_id: u64, issuer_schema_id: u64) -> CredentialRecord {
        CredentialRecord {
            credential_id,
            issuer_schema_id,
            genesis_issued_at: REQUEST_CREATED_AT,
            expires_at: REQUEST_CREATED_AT + 10_000,
            is_expired: false,
        }
    }

    /// One stored credential per issuer schema, with `credential_id == issuer_schema_id * 10`.
    fn records(issuer_schema_ids: &[u64]) -> Vec<CredentialRecord> {
        issuer_schema_ids
            .iter()
            .map(|&schema| record(schema * 10, schema))
            .collect()
    }

    fn ids(credential_ids: &[u64]) -> HashSet<u64> {
        credential_ids.iter().copied().collect()
    }

    fn selected_identifiers(
        request: &CoreProofRequest,
        records: &[CredentialRecord],
        filter: &CredentialFilter,
    ) -> Result<Vec<String>, WalletKitError> {
        select_credentials(request, records, filter).map(|selection| {
            selection
                .into_iter()
                .map(|selected| selected.identifier)
                .collect()
        })
    }

    #[test]
    fn allow_all_filter_matches_world_id_core_selection() {
        let constraints = [
            None,
            Some(serde_json::json!({ "any": ["passport", "orb"] })),
            Some(serde_json::json!({ "any": ["orb", "passport"] })),
            Some(serde_json::json!({ "all": ["passport", "orb"] })),
            Some(serde_json::json!({ "enumerate": ["passport", "orb", "selfie"] })),
            Some(
                serde_json::json!({ "all": ["device", { "any": ["passport", "orb"] }] }),
            ),
            Some(
                serde_json::json!({ "any": [{ "all": ["passport", "device"] }, "orb"] }),
            ),
            Some(serde_json::json!({
                "enumerate": [{ "any": ["selfie", "orb"] }, "passport", "device"]
            })),
        ];
        let stores: [&[u64]; 5] = [
            &[PASSPORT, ORB, DEVICE, SELFIE],
            &[ORB, DEVICE],
            &[PASSPORT],
            &[SELFIE, DEVICE],
            &[],
        ];

        for constraints in constraints {
            let request = request(standard_items(), constraints.clone());
            for &schemas in &stores {
                let expected = request
                    .credentials_to_prove(&schemas.iter().copied().collect())
                    .map(|items| {
                        items
                            .into_iter()
                            .map(|item| item.identifier.clone())
                            .collect::<Vec<_>>()
                    });
                let actual = selected_identifiers(
                    &request,
                    &records(schemas),
                    &CredentialFilter::new(),
                )
                .ok();
                assert_eq!(
                    actual, expected,
                    "constraints {constraints:?} with stored schemas {schemas:?}"
                );
            }
        }
    }

    #[test]
    fn requiring_any_of_picks_first_matching_alternative() {
        let request = request(
            standard_items(),
            Some(serde_json::json!({ "any": ["passport", "orb"] })),
        );
        let filter = CredentialFilter::new().requiring_any_of(ids(&[ORB * 10]));

        let selection =
            selected_identifiers(&request, &records(&[PASSPORT, ORB]), &filter);

        assert_eq!(selection.unwrap(), ["orb"]);
    }

    #[test]
    fn requiring_any_of_is_satisfied_by_any_part_of_the_selection() {
        // `orb` is required by the outer `all`, so the first `any` branch is kept even
        // though it does not contain the required credential itself.
        let request = request(
            standard_items(),
            Some(
                serde_json::json!({ "all": ["orb", { "any": ["device", "passport"] }] }),
            ),
        );
        let filter = CredentialFilter::new().requiring_any_of(ids(&[ORB * 10]));

        let selection =
            selected_identifiers(&request, &records(&[ORB, DEVICE]), &filter);

        assert_eq!(selection.unwrap(), ["orb", "device"]);
    }

    #[test]
    fn requiring_any_of_searches_nested_alternatives() {
        let request = request(
            standard_items(),
            Some(
                serde_json::json!({ "all": ["device", { "any": ["passport", "orb"] }] }),
            ),
        );
        let filter = CredentialFilter::new().requiring_any_of(ids(&[ORB * 10]));

        let selection =
            selected_identifiers(&request, &records(&[PASSPORT, ORB, DEVICE]), &filter);

        assert_eq!(selection.unwrap(), ["orb", "device"]);
    }

    #[test]
    fn requiring_any_of_inside_enumerate_switches_nested_alternative() {
        let request = request(
            standard_items(),
            Some(serde_json::json!({
                "enumerate": [{ "any": ["selfie", "orb"] }, "device"]
            })),
        );
        let filter = CredentialFilter::new().requiring_any_of(ids(&[ORB * 10]));

        let selection =
            selected_identifiers(&request, &records(&[ORB, DEVICE, SELFIE]), &filter);

        assert_eq!(selection.unwrap(), ["orb", "device"]);
    }

    #[test]
    fn requiring_any_of_fails_when_no_selection_contains_the_credentials() {
        let request = request(
            standard_items(),
            Some(serde_json::json!({ "any": ["passport", "orb"] })),
        );
        let filter = CredentialFilter::new().requiring_any_of(ids(&[ORB * 10]));

        let selection = selected_identifiers(&request, &records(&[PASSPORT]), &filter);

        assert!(matches!(
            selection,
            Err(WalletKitError::UnfulfillableRequest)
        ));
    }

    #[test]
    fn requiring_any_of_an_empty_set_accepts_nothing() {
        let request = request(vec![item("orb", ORB)], None);
        let filter = CredentialFilter::new().requiring_any_of(HashSet::new());

        let selection = selected_identifiers(&request, &records(&[ORB]), &filter);

        assert!(matches!(
            selection,
            Err(WalletKitError::UnfulfillableRequest)
        ));
    }

    #[test]
    fn excluded_credential_falls_back_to_older_version() {
        let request = request(vec![item("orb", ORB)], None);
        let newer = record(21, ORB);
        let older = record(20, ORB);
        let filter = CredentialFilter::new().excluding_credential_ids(ids(&[21]));

        let selection =
            select_credentials(&request, &[newer, older], &filter).expect("selection");

        assert_eq!(selection[0].credential_id, 20);
    }

    #[test]
    fn excluding_a_credential_moves_to_the_next_alternative() {
        let request = request(
            standard_items(),
            Some(serde_json::json!({ "any": ["passport", "orb"] })),
        );
        let filter =
            CredentialFilter::new().excluding_credential_ids(ids(&[PASSPORT * 10]));

        let selection =
            selected_identifiers(&request, &records(&[PASSPORT, ORB]), &filter);

        assert_eq!(selection.unwrap(), ["orb"]);
    }

    #[test]
    fn pinned_selection_uses_pinned_version_over_newer_one() {
        let request = request(vec![item("orb", ORB)], None);
        let newer = record(21, ORB);
        let older = record(20, ORB);
        let filter = CredentialFilter::new().pinned_to(ids(&[20]));

        let selection =
            select_credentials(&request, &[newer, older], &filter).expect("selection");

        assert_eq!(selection[0].credential_id, 20);
    }

    #[test]
    fn pinned_selection_fails_instead_of_proving_a_different_set() {
        let request = request(
            standard_items(),
            Some(serde_json::json!({ "enumerate": ["passport", "selfie"] })),
        );
        let pinned =
            CredentialFilter::new().pinned_to(ids(&[PASSPORT * 10, SELFIE * 10]));

        let passport_expired =
            select_credentials(&request, &records(&[SELFIE]), &pinned);

        assert!(matches!(
            passport_expired,
            Err(WalletKitError::UnfulfillableRequest)
        ));
    }

    #[test]
    fn pinned_selection_round_trips() {
        let request = request(
            standard_items(),
            Some(
                serde_json::json!({ "all": ["device", { "any": ["passport", "orb"] }] }),
            ),
        );
        let stored = records(&[PASSPORT, ORB, DEVICE]);
        let first = select_credentials(
            &request,
            &stored,
            &CredentialFilter::new().requiring_any_of(ids(&[ORB * 10])),
        )
        .expect("selection");
        let pinned = CredentialFilter::new().pinned_to(
            first
                .iter()
                .map(|selected| selected.credential_id)
                .collect(),
        );

        let second = select_credentials(&request, &stored, &pinned).expect("selection");

        assert_eq!(first, second);
    }

    #[test]
    fn selection_respects_item_time_constraints() {
        let mut passport = item("passport", PASSPORT);
        passport.genesis_issued_at_min = Some(REQUEST_CREATED_AT + 1);
        let mut orb = item("orb", ORB);
        orb.expires_at_min = Some(REQUEST_CREATED_AT + 10_000);
        let request = request(
            vec![passport, orb, item("device", DEVICE)],
            Some(serde_json::json!({ "any": ["passport", "orb", "device"] })),
        );

        let selection = selected_identifiers(
            &request,
            &records(&[PASSPORT, ORB, DEVICE]),
            &CredentialFilter::new(),
        );

        assert_eq!(selection.unwrap(), ["device"]);
    }

    #[test]
    fn expired_credentials_are_not_selected() {
        let request = request(vec![item("orb", ORB)], None);
        let mut expired = record(20, ORB);
        expired.is_expired = true;

        let selection =
            select_credentials(&request, &[expired], &CredentialFilter::new());

        assert!(matches!(
            selection,
            Err(WalletKitError::UnfulfillableRequest)
        ));
    }

    #[test]
    fn selected_credentials_are_returned_in_request_order() {
        let request = request(
            standard_items(),
            Some(serde_json::json!({ "all": ["selfie", "device", "passport"] })),
        );

        let selection = selected_identifiers(
            &request,
            &records(&[PASSPORT, DEVICE, SELFIE]),
            &CredentialFilter::new(),
        );

        assert_eq!(selection.unwrap(), ["passport", "device", "selfie"]);
    }

    #[test]
    fn constraints_beyond_protocol_limits_are_rejected() {
        let request = request(
            standard_items(),
            Some(serde_json::json!({
                "any": [{ "all": [{ "any": ["passport", "orb"] }, "device"] }]
            })),
        );

        let selection = select_credentials(
            &request,
            &records(&[PASSPORT, ORB, DEVICE]),
            &CredentialFilter::new(),
        );

        assert!(matches!(
            selection,
            Err(WalletKitError::InvalidInput { attribute, .. }) if attribute == "constraints"
        ));
    }

    #[test]
    fn store_selects_most_recent_credential_and_loads_it_by_id() {
        use crate::storage::tests_utils::{
            cleanup_test_storage, temp_root_path, InMemoryStorageProvider,
        };
        use crate::{Credential, FieldElement};
        use world_id_core::Credential as CoreCredential;

        let root = temp_root_path();
        let provider = InMemoryStorageProvider::new(&root);
        let store = CredentialStore::from_provider(&provider).expect("create store");
        store.init(42, REQUEST_CREATED_AT).expect("init");
        let store_orb = |genesis_issued_at: u64, now: u64| {
            let credential: Credential = CoreCredential::new()
                .issuer_schema_id(ORB)
                .genesis_issued_at(genesis_issued_at)
                .into();
            store
                .store_credential(
                    &credential,
                    &FieldElement::from(1u64),
                    REQUEST_CREATED_AT + 10_000,
                    None,
                    now,
                )
                .expect("store credential")
        };
        let older = store_orb(REQUEST_CREATED_AT, REQUEST_CREATED_AT);
        let newer = store_orb(REQUEST_CREATED_AT + 1, REQUEST_CREATED_AT + 1);
        let request = ProofRequest(request(vec![item("orb", ORB)], None));

        let selection = store
            .select_credentials(
                &request,
                &CredentialFilter::new(),
                REQUEST_CREATED_AT + 2,
            )
            .expect("selection");
        let pinned = store
            .select_credentials(
                &request,
                &CredentialFilter::new().pinned_to(ids(&[older])),
                REQUEST_CREATED_AT + 2,
            )
            .expect("pinned selection");
        let (loaded, _) = store.get_credential_by_id(older).expect("load by id");
        let missing = store.get_credential_by_id(newer + 1);

        assert_eq!(selection[0].credential_id, newer);
        assert_eq!(pinned[0].credential_id, older);
        assert_eq!(loaded.genesis_issued_at(), REQUEST_CREATED_AT);
        assert!(matches!(
            missing,
            Err(crate::storage::StorageError::CredentialIdNotFound { .. })
        ));

        cleanup_test_storage(&root);
    }
}
