//! The RPs a WIP-107 Billing Contract bills, from the indexer or the cached snapshot.

use alloy_core::primitives::Address;
use world_id_core::{
    api_types::IndexerBilledRpsResponse, primitives::rp::RpId, AuthenticatorError,
};

use super::Authenticator;
use crate::error::WalletKitError;
use crate::storage::{BilledRpsSnapshot, CredentialStore};

/// How long after its synced block a snapshot may answer for a lagging indexer.
pub const BILLED_RPS_MAX_AGE_SECS: u64 = 24 * 60 * 60;

/// Where a set of billed RPs came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BilledRpsSource {
    /// The indexer served it just now.
    Indexer,
    /// The indexer's Billing Contract sync is not current, so the last snapshot it served answers,
    /// at most [`BILLED_RPS_MAX_AGE_SECS`] after its synced block.
    Cache,
}

/// The RPs a Billing Contract bills, and where that answer came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BilledRps {
    /// The billed RPs as of the snapshot's synced block.
    pub snapshot: BilledRpsSnapshot,
    /// Whether the indexer served the snapshot just now.
    pub source: BilledRpsSource,
}

impl Authenticator {
    /// Fetches the RPs the WIP-107 Billing Contract at `billing_contract` bills, from the indexer.
    ///
    /// The indexer's answer is cached. While the indexer's Billing Contract sync is not current
    /// (`billing_not_synced` or `billing_sync_stale`), the cached snapshot answers instead, if its
    /// synced block is at most [`BILLED_RPS_MAX_AGE_SECS`] old.
    ///
    /// # Errors
    ///
    /// Returns an error if the indexer fails and no cached snapshot can answer, serves another
    /// chain or contract, or the cache cannot be read.
    pub async fn fetch_billed_rps(
        &self,
        billing_contract: Address,
        now: u64,
    ) -> Result<BilledRps, WalletKitError> {
        let fetched = self.inner.fetch_billed_rps(billing_contract).await;
        resolve(
            &self.store,
            self.inner.config.chain_id(),
            billing_contract,
            fetched,
            now,
        )
    }
}

/// Caches a fetched snapshot, or falls back to the cached one when the indexer's sync is not
/// current.
fn resolve(
    store: &CredentialStore,
    chain_id: u64,
    billing_contract: Address,
    fetched: Result<IndexerBilledRpsResponse, AuthenticatorError>,
    now: u64,
) -> Result<BilledRps, WalletKitError> {
    match fetched {
        Ok(response) => {
            let snapshot = BilledRpsSnapshot::new(
                response.block_number,
                response.synced_at,
                response
                    .billed_rp_ids
                    .into_iter()
                    .map(RpId::into_inner)
                    .collect(),
            );
            if let Err(error) = store.store_billed_rps(
                chain_id,
                billing_contract,
                &snapshot,
                now,
                snapshot.synced_at.saturating_add(BILLED_RPS_MAX_AGE_SECS),
            ) {
                tracing::error!(%billing_contract, "failed to cache the billed RPs: {error}");
            }
            Ok(BilledRps {
                snapshot,
                source: BilledRpsSource::Indexer,
            })
        }
        Err(
            error @ (AuthenticatorError::BillingNotSynced(_)
            | AuthenticatorError::BillingSyncStale(_)),
        ) => {
            let Some(snapshot) =
                store.get_billed_rps(chain_id, billing_contract, now)?
            else {
                return Err(error.into());
            };
            tracing::warn!(
                %billing_contract,
                block_number = snapshot.block_number,
                age_secs = now.saturating_sub(snapshot.synced_at),
                "the indexer's Billing Contract sync is not current; using the cached billed RPs: {error}"
            );
            Ok(BilledRps {
                snapshot,
                source: BilledRpsSource::Cache,
            })
        }
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use alloy_core::primitives::address;
    use world_id_core::api_types::IndexerBilledRpsResponse;

    use super::{
        resolve, AuthenticatorError, BilledRpsSnapshot, BilledRpsSource, RpId,
        BILLED_RPS_MAX_AGE_SECS,
    };
    use crate::storage::tests_utils::{
        cleanup_test_storage, temp_root_path, InMemoryStorageProvider,
    };
    use crate::storage::CredentialStore;

    const CHAIN_ID: u64 = 480;
    const CONTRACT: alloy_core::primitives::Address =
        address!("0x00000000000000000000000000000000000000b1");
    const SYNCED_AT: u64 = 1_794_000_000;

    fn response(rp_ids: &[u64]) -> IndexerBilledRpsResponse {
        IndexerBilledRpsResponse {
            chain_id: CHAIN_ID,
            billing_contract: CONTRACT,
            block_number: 1234,
            synced_at: SYNCED_AT,
            billed_rp_ids: rp_ids.iter().copied().map(RpId::new).collect(),
        }
    }

    fn with_store(test: impl FnOnce(&CredentialStore)) {
        let root = temp_root_path();
        let provider = InMemoryStorageProvider::new(&root);
        let store = CredentialStore::from_provider(&provider).expect("store");
        store.init(42, SYNCED_AT).expect("init storage");
        test(&store);
        cleanup_test_storage(&root);
    }

    fn not_synced() -> AuthenticatorError {
        AuthenticatorError::BillingNotSynced("not synced".to_string())
    }

    #[test]
    fn caches_the_indexer_snapshot() {
        with_store(|store| {
            let fetched =
                resolve(store, CHAIN_ID, CONTRACT, Ok(response(&[7, 3])), SYNCED_AT)
                    .expect("resolve");
            assert_eq!(fetched.source, BilledRpsSource::Indexer);
            assert_eq!(fetched.snapshot.rp_ids(), [3, 7]);
            assert_eq!(
                store
                    .get_billed_rps(CHAIN_ID, CONTRACT, SYNCED_AT)
                    .expect("get"),
                Some(fetched.snapshot)
            );
        });
    }

    #[test]
    fn falls_back_to_the_cache_while_the_sync_is_not_current() {
        with_store(|store| {
            resolve(store, CHAIN_ID, CONTRACT, Ok(response(&[7])), SYNCED_AT)
                .expect("fetch");
            for error in [
                not_synced(),
                AuthenticatorError::BillingSyncStale("stale".to_string()),
            ] {
                let cached =
                    resolve(store, CHAIN_ID, CONTRACT, Err(error), SYNCED_AT + 60)
                        .expect("cached snapshot");
                assert_eq!(cached.source, BilledRpsSource::Cache);
                assert!(cached.snapshot.is_billed(7));
            }
        });
    }

    #[test]
    fn a_new_snapshot_replaces_the_cached_one() {
        with_store(|store| {
            resolve(store, CHAIN_ID, CONTRACT, Ok(response(&[7])), SYNCED_AT)
                .expect("fetch");
            resolve(store, CHAIN_ID, CONTRACT, Ok(response(&[8])), SYNCED_AT)
                .expect("fetch");
            let cached =
                resolve(store, CHAIN_ID, CONTRACT, Err(not_synced()), SYNCED_AT)
                    .expect("cached snapshot");
            assert_eq!(cached.snapshot.rp_ids(), [8]);
        });
    }

    #[test]
    fn the_cache_expires_a_day_after_the_synced_block() {
        with_store(|store| {
            resolve(store, CHAIN_ID, CONTRACT, Ok(response(&[7])), SYNCED_AT)
                .expect("fetch");
            let last = SYNCED_AT + BILLED_RPS_MAX_AGE_SECS - 1;
            assert!(resolve(store, CHAIN_ID, CONTRACT, Err(not_synced()), last).is_ok());
            assert!(
                resolve(store, CHAIN_ID, CONTRACT, Err(not_synced()), last + 1)
                    .is_err()
            );
        });
    }

    #[test]
    fn other_errors_and_other_contracts_do_not_use_the_cache() {
        with_store(|store| {
            resolve(store, CHAIN_ID, CONTRACT, Ok(response(&[7])), SYNCED_AT)
                .expect("fetch");
            assert!(resolve(
                store,
                CHAIN_ID,
                CONTRACT,
                Err(AuthenticatorError::BillingNotIndexed),
                SYNCED_AT
            )
            .is_err());
            assert!(resolve(
                store,
                CHAIN_ID,
                CONTRACT,
                Err(AuthenticatorError::Generic("indexer down".to_string())),
                SYNCED_AT
            )
            .is_err());
            let other = address!("0x00000000000000000000000000000000000000b2");
            assert!(
                resolve(store, CHAIN_ID, other, Err(not_synced()), SYNCED_AT).is_err()
            );
            assert!(resolve(store, 1, CONTRACT, Err(not_synced()), SYNCED_AT).is_err());
        });
    }

    #[test]
    fn a_snapshot_already_past_its_age_is_not_cached() {
        with_store(|store| {
            let now = SYNCED_AT + BILLED_RPS_MAX_AGE_SECS;
            let fetched = resolve(store, CHAIN_ID, CONTRACT, Ok(response(&[7])), now)
                .expect("fetch");
            assert_eq!(fetched.source, BilledRpsSource::Indexer);
            assert_eq!(
                store.get_billed_rps(CHAIN_ID, CONTRACT, now).expect("get"),
                None::<BilledRpsSnapshot>
            );
        });
    }
}
