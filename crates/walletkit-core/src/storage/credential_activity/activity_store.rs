//! `CredentialActivityStore`: the public storage handle for credential-activity history.

use std::path::PathBuf;
#[cfg(not(target_arch = "wasm32"))]
use std::sync::mpsc;
use std::sync::{Arc, Mutex, MutexGuard};

use super::store::CredentialActivity;
use crate::storage::error::{StorageError, StorageResult};
use crate::storage::keys::IntermediateKeyHandle;
use crate::storage::paths::StoragePaths;
#[cfg(not(target_arch = "wasm32"))]
use crate::storage::remove_db_files;
#[cfg(not(target_arch = "wasm32"))]
use crate::storage::traits::{
    CredentialActivityChangedListener, CredentialActivitySchemaMigratedListener,
};
use crate::storage::types::{
    CredentialActivityEntry, CredentialActivityFinalization,
    CredentialActivityMetadata, CredentialActivityQuery, NewCredentialActivityEntry,
};

/// Storage handle for credential-activity history: a device-local,
/// chronological log of proof-share request outcomes.
///
/// Constructed and owned by the host app directly (not by
/// [`CredentialStore`](crate::storage::CredentialStore)). Keyed by the same
/// account `K_intermediate`, obtained via
/// [`CredentialStore::intermediate_key`](crate::storage::CredentialStore::intermediate_key)
/// and passed to [`open`](Self::open). Methods called before `open` return
/// [`StorageError::NotInitialized`].
#[derive(uniffi::Object)]
pub struct CredentialActivityStore {
    activity: Mutex<Option<OpenActivity>>,

    #[cfg(not(target_arch = "wasm32"))]
    activity_changed_tx: Mutex<Option<mpsc::SyncSender<()>>>,

    #[cfg(not(target_arch = "wasm32"))]
    activity_schema_migrated_tx: Mutex<Option<mpsc::SyncSender<(u32, u32)>>>,
}

/// The currently-open activity database, tagged with the path it was opened
/// at so a later [`CredentialActivityStore::open`] call with a different
/// path can be rejected instead of silently continuing to serve the
/// previous path's data.
struct OpenActivity {
    path: PathBuf,
    activity: CredentialActivity,
}

impl std::fmt::Debug for CredentialActivityStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialActivityStore").finish()
    }
}

#[uniffi::export]
impl CredentialActivityStore {
    /// Creates a handle. Does not open the database — call [`open`](Self::open).
    #[uniffi::constructor]
    #[must_use]
    pub const fn new() -> Self {
        Self {
            activity: Mutex::new(None),
            #[cfg(not(target_arch = "wasm32"))]
            activity_changed_tx: Mutex::new(None),
            #[cfg(not(target_arch = "wasm32"))]
            activity_schema_migrated_tx: Mutex::new(None),
        }
    }

    /// Opens the encrypted activity database under `paths`, applying pending
    /// migrations. A no-op if already open at the same path.
    ///
    /// # Errors
    ///
    /// Returns an error if the database cannot be opened or migrated, if the
    /// internal mutex is poisoned, or if the store is already open at a
    /// different path — call [`destroy_storage`](Self::destroy_storage) (or
    /// drop and recreate this handle) before opening a different account's
    /// activity database.
    #[allow(clippy::needless_pass_by_value)]
    pub fn open(
        &self,
        paths: Arc<StoragePaths>,
        key: Arc<IntermediateKeyHandle>,
    ) -> StorageResult<()> {
        let db_path = paths.credential_activity_db_path();

        // Held for the whole check-then-set below so a second `open()` call
        // racing this one can't both observe `None` and both proceed to
        // `CredentialActivity::new`.
        let mut guard = self.activity_lock()?;

        if let Some(open) = guard.as_ref() {
            return if open.path == db_path {
                Ok(())
            } else {
                Err(StorageError::CredentialActivityAlreadyOpen {
                    open_path: open.path.display().to_string(),
                    requested_path: db_path.display().to_string(),
                })
            };
        }

        let (activity, migrated) =
            key.with_exposed(|secret| CredentialActivity::new(&db_path, secret))?;

        *guard = Some(OpenActivity {
            path: db_path,
            activity,
        });

        drop(guard);

        if let Some((from_version, to_version)) = migrated {
            self.notify_activity_schema_migrated(from_version, to_version);
        }

        Ok(())
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[uniffi::export]
impl CredentialActivityStore {
    /// Deletes the activity database and drops any open handle. Call this
    /// alongside [`CredentialStore::destroy_storage`](crate::storage::CredentialStore::destroy_storage)
    /// — coordinating logout/account-deletion across storage objects is the
    /// host app's responsibility.
    ///
    /// # Errors
    ///
    /// Returns an error if the internal mutex is poisoned.
    #[allow(clippy::needless_pass_by_value)]
    pub fn destroy_storage(&self, paths: Arc<StoragePaths>) -> StorageResult<()> {
        *self.activity_lock()? = None;
        remove_db_files(&paths.credential_activity_db_path());

        Ok(())
    }
}

impl Default for CredentialActivityStore {
    fn default() -> Self {
        Self::new()
    }
}

impl CredentialActivityStore {
    fn activity_lock(&self) -> StorageResult<MutexGuard<'_, Option<OpenActivity>>> {
        self.activity.lock().map_err(|_| {
            StorageError::Lock("activity-store mutex poisoned".to_string())
        })
    }

    fn with_activity<T>(
        &self,
        f: impl FnOnce(&CredentialActivity) -> StorageResult<T>,
    ) -> StorageResult<T> {
        f(&self
            .activity_lock()?
            .as_ref()
            .ok_or(StorageError::NotInitialized)?
            .activity)
    }
}

#[uniffi::export]
impl CredentialActivityStore {
    /// Records the start of a proof-share request (approval screen shown).
    ///
    /// Returns the new entry's ID.
    ///
    /// A failure here must never fail the caller's proof-share flow — the
    /// swallow point belongs at the orchestration call site, not here; this
    /// method still returns a typed error so the caller can log it.
    ///
    /// # Errors
    ///
    /// Returns an error if the store is not initialized or the insert fails.
    pub fn record_activity_started(
        &self,
        entry: &NewCredentialActivityEntry,
        now: u64,
    ) -> StorageResult<u64> {
        let result =
            self.with_activity(|activity| activity.record_activity_started(entry, now));

        if result.is_ok() {
            self.notify_activity_changed();
        }

        result
    }

    /// Finalizes a previously started proof-share request, identified by the
    /// still-open entry matching `finalization.client_id`.
    ///
    /// # Errors
    ///
    /// Returns an error if the store is not initialized, no open entry
    /// matches `client_id`, or the update fails.
    pub fn finalize_activity(
        &self,
        finalization: &CredentialActivityFinalization,
        now: u64,
    ) -> StorageResult<()> {
        let result = self
            .with_activity(|activity| activity.finalize_activity(finalization, now));

        if result.is_ok() {
            self.notify_activity_changed();
        }

        result
    }

    /// Lists activity entries, most recent first.
    ///
    /// # Errors
    ///
    /// Returns an error if the store is not initialized or the query fails.
    pub fn list_activities(
        &self,
        query: Option<CredentialActivityQuery>,
        limit: u32,
        offset: u32,
    ) -> StorageResult<Vec<CredentialActivityEntry>> {
        self.with_activity(|activity| {
            activity.list_activities(query.as_ref(), limit, offset)
        })
    }

    /// Returns aggregate credential-activity metadata.
    ///
    /// # Errors
    ///
    /// Returns an error if the store is not initialized or the query fails.
    pub fn activity_metadata(&self) -> StorageResult<CredentialActivityMetadata> {
        self.with_activity(CredentialActivity::activity_metadata)
    }

    /// Marks pending entries (`outcome IS NULL`) as
    /// [`CredentialActivityOutcome::Incomplete`](crate::storage::CredentialActivityOutcome::Incomplete).
    /// Not run automatically — call explicitly, e.g. once at launch after
    /// [`CredentialStore::init`](crate::storage::CredentialStore::init).
    /// `exclude_client_ids` skips requests the host app intends to resume
    /// itself. Idempotent. Fires the activity-changed listener on success,
    /// same as [`record_activity_started`](Self::record_activity_started)
    /// and [`finalize_activity`](Self::finalize_activity), even if no entry
    /// actually needed reconciling.
    ///
    /// # Errors
    ///
    /// Returns an error if the store is not initialized or the update fails.
    #[allow(clippy::needless_pass_by_value)]
    pub fn reconcile_incomplete(
        &self,
        now: u64,
        exclude_client_ids: Vec<String>,
    ) -> StorageResult<()> {
        let result = self.with_activity(|activity| {
            activity.reconcile_incomplete(now, &exclude_client_ids)
        });

        if result.is_ok() {
            self.notify_activity_changed();
        }

        result
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[uniffi::export]
impl CredentialActivityStore {
    /// Registers a listener that is called after activity history changes
    /// (a start, finalize, or reconciliation was recorded).
    ///
    /// Only one listener can be active at a time — calling this replaces any
    /// previously registered listener. The previous delivery thread shuts down
    /// automatically when the old sender is dropped.
    ///
    /// Delivery happens on a dedicated background thread to avoid re-entering
    /// the `UniFFI` call stack (see `logger.rs` for rationale).
    ///
    /// **Warning:** the listener **must not** call back into this
    /// `CredentialActivityStore` — doing so will deadlock.
    pub fn set_activity_changed_listener(
        &self,
        listener: Arc<dyn CredentialActivityChangedListener>,
    ) {
        let (tx, rx) = mpsc::sync_channel(1);

        let spawn_result = std::thread::Builder::new()
            .name("walletkit-activity-notify".into())
            .spawn(move || {
                for () in rx {
                    listener.on_activity_changed();
                }
            });

        match spawn_result {
            Ok(_) => {
                if let Ok(mut guard) = self.activity_changed_tx.lock() {
                    *guard = Some(tx);
                }
            }
            Err(e) => {
                tracing::error!("failed to spawn activity notification thread: {e}");
            }
        }
    }

    /// Registers a listener notified once, informationally, if opening the
    /// credential-activity store applied one or more pending schema
    /// migrations.
    ///
    /// Register on this handle before calling [`open`](Self::open) to
    /// observe a migration that happens during this session's first open —
    /// migrations run during `open`, so a listener registered afterward
    /// misses it.
    ///
    /// **Warning:** the listener **must not** call back into this
    /// `CredentialActivityStore` — doing so will deadlock.
    pub fn set_activity_schema_migrated_listener(
        &self,
        listener: Arc<dyn CredentialActivitySchemaMigratedListener>,
    ) {
        let (tx, rx) = mpsc::sync_channel(1);

        let spawn_result = std::thread::Builder::new()
            .name("walletkit-activity-schema-notify".into())
            .spawn(move || {
                for (from_version, to_version) in rx {
                    listener.on_activity_schema_migrated(from_version, to_version);
                }
            });

        match spawn_result {
            Ok(_) => {
                if let Ok(mut guard) = self.activity_schema_migrated_tx.lock() {
                    *guard = Some(tx);
                }
            }
            Err(e) => {
                tracing::error!(
                    "failed to spawn activity-schema-migrated notification thread: {e}"
                );
            }
        }
    }
}

impl CredentialActivityStore {
    /// Best-effort notification to the registered activity-changed listener.
    /// No-op on wasm32 where the listener cannot be registered.
    fn notify_activity_changed(&self) {
        #[cfg(not(target_arch = "wasm32"))]
        match self.activity_changed_tx.lock() {
            Ok(guard) => {
                if let Some(tx) = guard.as_ref() {
                    match tx.try_send(()) {
                        Ok(()) | Err(mpsc::TrySendError::Full(())) => {}
                        Err(mpsc::TrySendError::Disconnected(())) => {
                            tracing::warn!("activity-changed listener disconnected");
                        }
                    }
                }
            }
            Err(_) => {
                tracing::warn!(
                    "activity-changed-tx mutex poisoned; dropping notification"
                );
            }
        }
    }

    /// Best-effort, one-shot notification to the registered
    /// activity-schema-migrated listener. No-op on wasm32.
    #[allow(unused_variables)]
    fn notify_activity_schema_migrated(&self, from_version: u32, to_version: u32) {
        #[cfg(not(target_arch = "wasm32"))]
        match self.activity_schema_migrated_tx.lock() {
            Ok(guard) => {
                if let Some(tx) = guard.as_ref() {
                    match tx.try_send((from_version, to_version)) {
                        Ok(()) | Err(mpsc::TrySendError::Full(_)) => {}
                        Err(mpsc::TrySendError::Disconnected(_)) => {
                            tracing::warn!(
                                "activity-schema-migrated listener disconnected"
                            );
                        }
                    }
                }
            }
            Err(_) => {
                tracing::warn!(
                    "activity-schema-migrated-tx mutex poisoned; dropping notification"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::credential_storage::CredentialStore;
    use crate::storage::tests_utils::{
        cleanup_test_storage, temp_root_path, InMemoryStorageProvider,
    };
    use crate::storage::types::{
        CredentialActivityFailureReason, CredentialActivityOutcome,
        CredentialActivityProtocol,
    };
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Mutex as StdMutex;

    struct TestActivityListener(Arc<AtomicU32>);

    impl CredentialActivityChangedListener for TestActivityListener {
        fn on_activity_changed(&self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct TestActivitySchemaMigratedListener(Arc<StdMutex<Vec<(u32, u32)>>>);

    impl CredentialActivitySchemaMigratedListener for TestActivitySchemaMigratedListener {
        fn on_activity_schema_migrated(&self, from_version: u32, to_version: u32) {
            self.0.lock().unwrap().push((from_version, to_version));
        }
    }

    fn wait_for_listener_count(count: &AtomicU32, expected: u32) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        loop {
            if count.load(Ordering::SeqCst) >= expected {
                return;
            }

            assert!(
                std::time::Instant::now() < deadline,
                "deadline exceeded while waiting for listener count to reach {expected}",
            );

            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    fn open_activity_store(store: &CredentialStore) -> Arc<CredentialActivityStore> {
        let activity_store = Arc::new(CredentialActivityStore::new());
        let paths = Arc::new(store.storage_paths().expect("storage paths"));
        let key = store.intermediate_key().expect("intermediate key");
        activity_store
            .open(paths, key)
            .expect("open activity store");

        activity_store
    }

    fn sample_activity_entry() -> NewCredentialActivityEntry {
        NewCredentialActivityEntry {
            app_identifier: "app_worldcoin".to_string(),
            client_id: "bridge-request-1".to_string(),
            request_id: None,
            protocol: CredentialActivityProtocol::V3,
            credentials: vec![],
        }
    }

    #[test]
    fn test_record_and_finalize_activity_through_store() {
        let root = temp_root_path();
        let provider = InMemoryStorageProvider::new(&root);
        let store = CredentialStore::from_provider(&provider).expect("create store");
        store.init(42, 1000).expect("init storage");

        let activity_store = open_activity_store(&store);
        activity_store
            .record_activity_started(&sample_activity_entry(), 1000)
            .expect("record activity");

        activity_store
            .finalize_activity(
                &CredentialActivityFinalization {
                    client_id: sample_activity_entry().client_id,
                    outcome: CredentialActivityOutcome::Shared,
                    failure_reason: None,
                    protocol: CredentialActivityProtocol::V3,
                    credentials: vec![],
                },
                1100,
            )
            .expect("finalize activity");

        let entries = activity_store
            .list_activities(None, 10, 0)
            .expect("list activities");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].outcome, Some(CredentialActivityOutcome::Shared));

        let metadata = activity_store
            .activity_metadata()
            .expect("activity metadata");

        assert_eq!(metadata.total_count, 1);

        cleanup_test_storage(&root);
    }

    #[test]
    fn test_activity_changed_listener_notified_on_record_and_finalize() {
        let root = temp_root_path();
        let provider = InMemoryStorageProvider::new(&root);
        let store = CredentialStore::from_provider(&provider).expect("create store");
        store.init(42, 1000).expect("init storage");

        let activity_store = open_activity_store(&store);
        let count = Arc::new(AtomicU32::new(0));
        activity_store.set_activity_changed_listener(Arc::new(TestActivityListener(
            Arc::clone(&count),
        )));

        activity_store
            .record_activity_started(&sample_activity_entry(), 1000)
            .expect("record activity");

        wait_for_listener_count(&count, 1);

        activity_store
            .finalize_activity(
                &CredentialActivityFinalization {
                    client_id: sample_activity_entry().client_id,
                    outcome: CredentialActivityOutcome::Declined,
                    failure_reason: None,
                    protocol: CredentialActivityProtocol::V3,
                    credentials: vec![],
                },
                1100,
            )
            .expect("finalize activity");

        wait_for_listener_count(&count, 2);

        cleanup_test_storage(&root);
    }

    #[test]
    fn test_activity_changed_listener_not_notified_on_failure() {
        let root = temp_root_path();
        let provider = InMemoryStorageProvider::new(&root);
        let store = CredentialStore::from_provider(&provider).expect("create store");
        store.init(42, 1000).expect("init storage");

        let activity_store = open_activity_store(&store);
        let count = Arc::new(AtomicU32::new(0));
        activity_store.set_activity_changed_listener(Arc::new(TestActivityListener(
            Arc::clone(&count),
        )));

        let result = activity_store.finalize_activity(
            &CredentialActivityFinalization {
                client_id: "no-such-request".to_string(),
                outcome: CredentialActivityOutcome::Failed,
                failure_reason: Some(CredentialActivityFailureReason::NetworkError),
                protocol: CredentialActivityProtocol::V3,
                credentials: vec![],
            },
            1000,
        );

        assert!(result.is_err());

        std::thread::sleep(std::time::Duration::from_millis(50));
        assert_eq!(
            count.load(Ordering::SeqCst),
            0,
            "listener should not be notified when finalize fails"
        );

        cleanup_test_storage(&root);
    }

    #[test]
    fn test_activity_schema_migrated_listener_notified_once_on_first_open() {
        let root = temp_root_path();
        let provider = InMemoryStorageProvider::new(&root);
        let store = CredentialStore::from_provider(&provider).expect("create store");
        store.init(42, 1000).expect("init storage");

        let activity_store = Arc::new(CredentialActivityStore::new());
        let events = Arc::new(StdMutex::new(Vec::new()));
        activity_store.set_activity_schema_migrated_listener(Arc::new(
            TestActivitySchemaMigratedListener(Arc::clone(&events)),
        ));

        let paths = Arc::new(store.storage_paths().expect("paths"));
        let key = store.intermediate_key().expect("key");

        activity_store
            .open(Arc::clone(&paths), Arc::clone(&key))
            .expect("open activity store");

        std::thread::sleep(std::time::Duration::from_millis(50));

        assert_eq!(
            *events.lock().unwrap(),
            vec![(0, 1)],
            "fresh database should report a single migration from 0 to 1"
        );

        // Re-opening an already-open store must not fire again.
        activity_store
            .open(paths, key)
            .expect("re-open activity store");

        std::thread::sleep(std::time::Duration::from_millis(50));
        assert_eq!(events.lock().unwrap().len(), 1);

        cleanup_test_storage(&root);
    }

    #[test]
    fn test_reconcile_incomplete_marks_pending_activity_as_incomplete_on_reopen() {
        let root = temp_root_path();

        // Reuse one provider (same in-memory keystore/blob-store) across both
        // `CredentialStore` instances below — a fresh `InMemoryStorageProvider`
        // would mint a new random key envelope and fail to open the files the
        // first instance already wrote, which isn't the scenario under test.
        // A real app's Keychain-backed keystore persists across restarts;
        // this mirrors that by keeping the provider alive.
        let provider = InMemoryStorageProvider::new(&root);

        {
            let store =
                CredentialStore::from_provider(&provider).expect("create store");
            store.init(42, 1000).expect("init storage");
            open_activity_store(&store)
                .record_activity_started(&sample_activity_entry(), 1000)
                .expect("record activity");
            // Simulate the app being killed before finalize ran: `store`
            // (and its lock) drops here without a terminal write.
        }

        let store = CredentialStore::from_provider(&provider).expect("recreate store");
        store.init(42, 2000).expect("re-init storage");

        let activity_store = open_activity_store(&store);

        let entries = activity_store
            .list_activities(None, 10, 0)
            .expect("list before reconcile");

        assert_eq!(
            entries[0].outcome, None,
            "opening alone must not reconcile pending entries"
        );

        activity_store
            .reconcile_incomplete(2000, vec![])
            .expect("reconcile");

        let entries = activity_store
            .list_activities(None, 10, 0)
            .expect("list after reconcile");

        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].outcome,
            Some(CredentialActivityOutcome::Incomplete),
            "entry left pending across a restart should reconcile to Incomplete"
        );

        cleanup_test_storage(&root);
    }

    #[test]
    fn test_open_with_different_path_while_open_is_rejected() {
        let root = temp_root_path();
        let provider = InMemoryStorageProvider::new(&root);
        let store = CredentialStore::from_provider(&provider).expect("create store");
        store.init(42, 1000).expect("init storage");

        let activity_store = open_activity_store(&store);

        let other_paths = Arc::new(StoragePaths::new(root.join("other-account")));
        let key = store.intermediate_key().expect("intermediate key");
        let err = activity_store
            .open(other_paths, key)
            .expect_err("opening at a different path while open should fail");

        assert!(matches!(
            err,
            StorageError::CredentialActivityAlreadyOpen { .. }
        ));

        cleanup_test_storage(&root);
    }

    #[test]
    fn test_open_with_same_path_while_open_is_a_no_op() {
        let root = temp_root_path();
        let provider = InMemoryStorageProvider::new(&root);
        let store = CredentialStore::from_provider(&provider).expect("create store");
        store.init(42, 1000).expect("init storage");

        let activity_store = open_activity_store(&store);
        let paths = Arc::new(store.storage_paths().expect("storage paths"));
        let key = store.intermediate_key().expect("intermediate key");

        activity_store
            .open(paths, key)
            .expect("re-opening at the same path should be a no-op");

        cleanup_test_storage(&root);
    }

    #[test]
    fn test_destroy_storage_removes_activity_files() {
        let root = temp_root_path();
        let provider = InMemoryStorageProvider::new(&root);
        let store = CredentialStore::from_provider(&provider).expect("create store");
        store.init(42, 1000).expect("init storage");

        let activity_store = open_activity_store(&store);
        activity_store
            .record_activity_started(&sample_activity_entry(), 1000)
            .expect("record activity");

        // Destroying storage is the host app's job to coordinate across both
        // objects — `CredentialStore::destroy_storage` no longer touches
        // activity data on its own.
        let paths = Arc::new(store.storage_paths().expect("paths"));
        store.destroy_storage().expect("destroy storage");
        activity_store
            .destroy_storage(Arc::clone(&paths))
            .expect("destroy activity storage");

        assert!(!paths.credential_activity_db_path().exists());

        // Re-initialization should work and start with an empty activity log.
        store.init(42, 1000).expect("re-init storage");

        let entries = open_activity_store(&store)
            .list_activities(None, 10, 0)
            .expect("list after re-init");

        assert!(entries.is_empty());

        cleanup_test_storage(&root);
    }
}
