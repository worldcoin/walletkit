#![cfg(feature = "storage")]

mod common;

use walletkit_core::storage::CredentialStore;

#[test]
fn test_storage_flow_end_to_end() {
    let root = common::temp_root();
    let provider = common::InMemoryStorageProvider::new(&root);
    let store = CredentialStore::from_provider(&provider).expect("store");

    store.init(42, 100).expect("init");

    let credential_id = store
        .store_credential(
            7,
            vec![0x11u8; 32],
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

    let root_bytes = vec![0xAAu8; 32];
    store
        .merkle_cache_put(1, root_bytes.clone(), vec![9, 9], 100, 10)
        .expect("cache put");
    let valid_before = 105;
    let hit = store
        .merkle_cache_get(1, root_bytes.clone(), valid_before)
        .expect("cache get");
    assert_eq!(hit, Some(vec![9, 9]));
    let miss = store
        .merkle_cache_get(1, root_bytes, 111)
        .expect("cache get");
    assert!(miss.is_none());

    // FIXME
    // let request_id = [0xABu8; 32];
    // let nullifier = [0xCDu8; 32];
    // let fresh = CredentialStorage::begin_replay_guard(
    //     &mut store,
    //     request_id,
    //     nullifier,
    //     vec![1, 2],
    //     200,
    //     50,
    // )
    // .expect("disclose");
    // assert_eq!(
    //     fresh,
    //     ReplayGuardResult {
    //         kind: ReplayGuardKind::Fresh,
    //         bytes: vec![1, 2],
    //     }
    // );
    // let cached = CredentialStorage::is_nullifier_replay(&store, request_id, 210)
    //     .expect("disclosure lookup");
    // assert_eq!(cached, Some(vec![1, 2]));
    // let replay = CredentialStorage::begin_replay_guard(
    //     &mut store,
    //     request_id,
    //     nullifier,
    //     vec![9, 9],
    //     201,
    //     50,
    // )
    // .expect("replay");
    // assert_eq!(
    //     replay,
    //     ReplayGuardResult {
    //         kind: ReplayGuardKind::Replay,
    //         bytes: vec![1, 2],
    //     }
    // );

    common::cleanup_storage(&root);
}
