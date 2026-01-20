use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

use walletkit_core::storage::tests_utils::InMemoryStorageProvider;
use walletkit_core::storage::{
    CredentialStorage, CredentialStore, CredentialStatus, ProofDisclosureResult,
    StoragePaths,
};

fn temp_root() -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!("walletkit-storage-{}", Uuid::new_v4()));
    path
}

fn cleanup_storage(root: &Path) {
    let paths = StoragePaths::new(root);
    let vault = paths.vault_db_path();
    let cache = paths.cache_db_path();
    let lock = paths.lock_path();
    let _ = fs::remove_file(&vault);
    let _ = fs::remove_file(vault.with_extension("sqlite-wal"));
    let _ = fs::remove_file(vault.with_extension("sqlite-shm"));
    let _ = fs::remove_file(&cache);
    let _ = fs::remove_file(cache.with_extension("sqlite-wal"));
    let _ = fs::remove_file(cache.with_extension("sqlite-shm"));
    let _ = fs::remove_file(lock);
    let _ = fs::remove_dir_all(paths.worldid_dir());
    let _ = fs::remove_dir_all(paths.root());
}

#[test]
fn test_storage_flow_end_to_end() {
    let root = temp_root();
    let provider = InMemoryStorageProvider::new(&root);
    let mut store = CredentialStore::from_provider(&provider).expect("store");

    store.init(42, 100).expect("init");

    let credential_id = store
        .store_credential(
            7,
            CredentialStatus::Active,
            [0x11u8; 32],
            1_700_000_000,
            Some(1_800_000_000),
            vec![1, 2, 3],
            Some(vec![4, 5, 6]),
            100,
        )
        .expect("store credential");

    let records = store.list_credentials(None, 101).expect("list credentials");
    assert_eq!(records.len(), 1);
    let record = &records[0];
    assert_eq!(record.credential_id, credential_id);
    assert_eq!(record.issuer_schema_id, 7);
    assert_eq!(record.subject_blinding_factor, [0x11u8; 32]);
    assert_eq!(record.credential_blob, vec![1, 2, 3]);
    assert_eq!(record.associated_data.as_deref(), Some(&[4, 5, 6][..]));

    let root_bytes = [0xAAu8; 32];
    store
        .merkle_cache_put(1, root_bytes, vec![9, 9], 100, 10)
        .expect("cache put");
    let hit = store
        .merkle_cache_get(1, root_bytes, 105)
        .expect("cache get");
    assert_eq!(hit, Some(vec![9, 9]));
    let miss = store
        .merkle_cache_get(1, root_bytes, 111)
        .expect("cache get");
    assert!(miss.is_none());

    let request_id = [0xABu8; 32];
    let nullifier = [0xCDu8; 32];
    let fresh = store
        .begin_proof_disclosure(request_id, nullifier, vec![1, 2], 200, 50)
        .expect("disclose");
    assert_eq!(fresh, ProofDisclosureResult::Fresh(vec![1, 2]));
    let replay = store
        .begin_proof_disclosure(request_id, nullifier, vec![9, 9], 201, 50)
        .expect("replay");
    assert_eq!(replay, ProofDisclosureResult::Replay(vec![1, 2]));

    cleanup_storage(&root);
}
