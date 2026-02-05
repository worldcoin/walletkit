#![cfg(feature = "storage")]

mod common;

use rand::rngs::OsRng;
use walletkit_core::storage::CredentialStore;
use world_id_core::FieldElement as CoreFieldElement;

#[test]
fn test_storage_flow_end_to_end() {
    let root = common::temp_root();
    let provider = common::InMemoryStorageProvider::new(&root);
    let store = CredentialStore::from_provider(&provider).expect("store");

    store.init(42, 100).expect("init");

    let blinding_factor = CoreFieldElement::random(&mut OsRng);

    let credential_id = store
        .store_credential(
            7,
            &blinding_factor.into(),
            1_700_000_000,
            1_800_000_000,
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
    assert_eq!(record.expires_at, 1_800_000_000);

    store
        .merkle_cache_put(vec![9, 9], 100, 10)
        .expect("cache put");
    let now = 105;
    let hit = store.merkle_cache_get(now).expect("cache get");
    assert_eq!(hit, Some(vec![9, 9]));
    let miss = store.merkle_cache_get(111).expect("cache get");
    assert!(miss.is_none());

    common::cleanup_storage(&root);
}
