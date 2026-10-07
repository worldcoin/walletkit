use super::{
    authenticator::*, callbacks::*, identity::*, storage::*, v3::*, Buffer, ByteSlice,
    FieldElementHandle, OperationHandle, StoragePathsHandle, *,
};
use crate::native::{
    codec,
    operation::{Operation, OperationState},
    registry,
};
use std::{
    collections::HashMap,
    ffi::c_void,
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc, Arc, Mutex,
    },
};
use walletkit_core::{
    flamingo::RequestIntegrityError,
    storage::types::{
        ActivityEntry, ActivityFailureReason, ActivityOutcome, ProtocolVersion,
    },
    FieldElement,
};

#[test]
fn field_elements_round_trip_and_stale_or_mistyped_handles_fail() {
    unsafe {
        let mut element = FieldElementHandle { id: 0 };
        let mut error = Buffer::empty();
        assert!(walletkit_field_element_from_u64(
            u64::MAX,
            &raw mut element,
            &raw mut error
        ));
        let mut bytes = Buffer::empty();
        assert!(walletkit_field_element_to_bytes(
            element,
            &raw mut bytes,
            &raw mut error
        ));
        let bytes = bytes.take().unwrap();
        assert_eq!(&bytes[24..], &[255; 8]);

        let mut restored = FieldElementHandle { id: 0 };
        assert!(walletkit_field_element_from_bytes(
            ByteSlice::from_slice(&bytes),
            &raw mut restored,
            &raw mut error
        ));
        let mut hex = Buffer::empty();
        assert!(walletkit_field_element_to_hex_string(
            restored,
            &raw mut hex,
            &raw mut error
        ));
        assert_eq!(
            String::from_utf8(hex.take().unwrap()).unwrap(),
            format!("0x{}{}", "0".repeat(48), "f".repeat(16))
        );

        let wrong = StoragePathsHandle { id: element.id };
        let mut path = Buffer::empty();
        assert!(!walletkit_storage_paths_root_path_string(
            wrong,
            &raw mut path,
            &raw mut error
        ));
        assert_eq!(bridge_code(&mut error), "InvalidHandle");

        walletkit_object_release(element.id);
        walletkit_object_release(element.id);
        walletkit_object_release(restored.id);
        let mut stale = Buffer::empty();
        assert!(!walletkit_field_element_to_bytes(
            element,
            &raw mut stale,
            &raw mut error
        ));
        assert_eq!(bridge_code(&mut error), "InvalidHandle");
        assert!(stale.data.is_null());
    }
}

#[test]
fn invalid_input_is_rejected_with_typed_errors() {
    unsafe {
        let mut element = FieldElementHandle { id: 0 };
        let mut error = Buffer::empty();
        assert!(!walletkit_field_element_from_bytes(
            ByteSlice::from_slice(&[1; 3]),
            &raw mut element,
            &raw mut error
        ));
        assert_eq!(error.take().unwrap()[0], 1, "WalletKitError domain");
        assert_eq!(element.id, 0);

        let mut paths = StoragePathsHandle { id: 0 };
        let mut error = Buffer::empty();
        assert!(!walletkit_storage_paths_from_root(
            ByteSlice::from_slice(&[0xff]),
            &raw mut paths,
            &raw mut error
        ));
        assert_eq!(bridge_code(&mut error), "InvalidInput");

        let mut level = Buffer::empty();
        assert!(!walletkit_emit_log(
            9,
            ByteSlice::from_slice(b"x"),
            &raw mut level
        ));
        assert_eq!(bridge_code(&mut level), "InvalidInput");

        assert!(!walletkit_field_element_from_u64(
            1,
            std::ptr::null_mut(),
            &raw mut error
        ));
    }
}

#[test]
fn credential_store_round_trips_binary_records_through_host_callbacks() {
    let root = tempfile::tempdir().unwrap();
    let host = MemoryHost::default();
    unsafe {
        let paths = storage_paths(root.path().to_str().unwrap());
        let store = open_store(paths, &host);
        let mut error = Buffer::empty();
        let changed = Arc::new(AtomicUsize::new(0));
        assert!(walletkit_credential_store_set_activity_changed_listener(
            store,
            ActivityChangedListenerCallbacks {
                context: Arc::into_raw(Arc::clone(&changed)).cast_mut().cast(),
                on_activity_changed: count,
                release: release_counter,
            },
            &raw mut error
        ));

        let entry = ActivityEntry {
            id: None,
            rp_id: u64::MAX,
            app_identifier: "app".into(),
            client_id: "request".into(),
            protocol: ProtocolVersion::V4,
            timestamp: Some(100),
            outcome: ActivityOutcome::Failed,
            issuer_schema_ids: vec![7, u64::MAX],
            failure_reason: Some(ActivityFailureReason::Timeout),
        };
        let encoded = codec::encode(entry.clone()).unwrap().claim();
        let mut id = 0;
        assert!(walletkit_credential_store_record_activity(
            store,
            ByteSlice::from_slice(&encoded),
            100,
            &raw mut id,
            &raw mut error
        ));

        let mut list = Buffer::empty();
        assert!(walletkit_credential_store_list_activities(
            store,
            std::ptr::null(),
            10,
            0,
            &raw mut list,
            &raw mut error
        ));
        let mut entries: Vec<ActivityEntry> =
            codec::decode(&list.take().unwrap()).unwrap();
        entries[0].issuer_schema_ids.sort_unstable();
        assert_eq!(
            entries,
            vec![ActivityEntry {
                id: Some(id),
                ..entry
            }]
        );

        let filter = 9;
        let mut filtered = Buffer::empty();
        assert!(walletkit_credential_store_list_activities(
            store,
            &raw const filter,
            10,
            0,
            &raw mut filtered,
            &raw mut error
        ));
        assert_eq!(filtered.take().unwrap(), 0_u32.to_le_bytes());

        let mut total = 0;
        assert!(walletkit_credential_store_activity_metadata(
            store,
            &raw mut total,
            &raw mut error
        ));
        assert_eq!(total, 1);
        for _ in 0..500 {
            if changed.load(Ordering::SeqCst) > 0 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(changed.load(Ordering::SeqCst), 1);

        walletkit_object_release(store.id);
        let reopened = open_store(paths, &host);
        assert!(walletkit_credential_store_activity_metadata(
            reopened,
            &raw mut total,
            &raw mut error
        ));
        assert_eq!(total, 1);
        walletkit_object_release(reopened.id);
        walletkit_object_release(paths.id);
    }
    assert_eq!(
        Arc::strong_count(&host.blobs),
        1,
        "callback tables released"
    );
}

#[test]
fn callback_tables_are_released_when_the_call_fails() {
    let host = MemoryHost::default();
    let mut store = CredentialStoreHandle { id: 0 };
    let mut error = Buffer::empty();
    unsafe {
        assert!(!walletkit_credential_store_new_with_components(
            StoragePathsHandle { id: 0 },
            host.keystore(),
            host.blob_store(),
            &raw mut store,
            &raw mut error,
        ));
        assert_eq!(bridge_code(&mut error), "InvalidHandle");
    }
    assert_eq!(Arc::strong_count(&host.blobs), 1);
}

#[test]
fn host_storage_errors_keep_their_variant_and_other_failures_stay_opaque() {
    let root = tempfile::tempdir().unwrap();
    unsafe {
        let paths = storage_paths(root.path().to_str().unwrap());
        for (seal, expected) in [
            (failing_seal as SealFn, "denied"),
            (opaque_seal as SealFn, "HostFailure"),
            (empty_seal as SealFn, "MissingResult"),
        ] {
            let host = MemoryHost::default();
            let mut keystore = host.keystore();
            keystore.seal = seal;
            let mut store = CredentialStoreHandle { id: 0 };
            let mut error = Buffer::empty();
            assert!(walletkit_credential_store_new_with_components(
                paths,
                keystore,
                host.blob_store(),
                &raw mut store,
                &raw mut error,
            ));
            assert!(!walletkit_credential_store_initialize(
                store,
                42,
                100,
                &raw mut error
            ));
            let bytes = error.take().unwrap();
            assert_eq!(bytes[..2], [2, 0], "StorageError::Keystore");
            let message = String::from_utf8_lossy(&bytes[6..]);
            assert!(message.contains(expected), "{message}");
            walletkit_object_release(store.id);
        }
        walletkit_object_release(paths.id);
    }
}

#[test]
fn cancellation_before_start_runs_nothing() {
    unsafe {
        let mut operation = OperationHandle { id: 0 };
        let mut error = Buffer::empty();
        assert!(walletkit_operation_new(&raw mut operation, &raw mut error));
        walletkit_operation_cancel(operation);
        let mut proof = MerkleTreeProofHandle { id: 0 };
        assert!(!walletkit_merkle_tree_proof_from_identity_commitment(
            operation,
            Uint256 { bytes: [0; 32] },
            ByteSlice::from_slice(b"https://example.invalid"),
            false,
            &raw mut proof,
            &raw mut error,
        ));
        assert_eq!(bridge_code(&mut error), "Cancelled");
        assert_eq!(proof.id, 0);
        assert!(!walletkit_merkle_tree_proof_from_identity_commitment(
            operation,
            Uint256 { bytes: [0; 32] },
            ByteSlice::from_slice(b"https://example.invalid"),
            false,
            &raw mut proof,
            &raw mut error,
        ));
        assert_eq!(bridge_code(&mut error), "OperationAlreadyStarted");
        walletkit_object_release(operation.id);
    }
}

#[test]
fn cancellation_in_flight_drops_the_future_and_its_retained_inputs() {
    let field = Arc::new(FieldElement::from_u64(42));
    let weak = Arc::downgrade(&field);
    let handle = registry::insert(field).unwrap();
    let state = Arc::new(OperationState::new());
    let operation = Operation(Arc::clone(&state));
    let (started, receiver) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        let retained = registry::get::<FieldElement>(handle).unwrap();
        operation.run(async move {
            started.send(()).unwrap();
            std::future::pending::<()>().await;
            drop(retained);
            Ok(())
        })
    });
    receiver
        .recv_timeout(std::time::Duration::from_secs(5))
        .unwrap();
    registry::release(handle);
    assert!(weak.upgrade().is_some(), "running call keeps its input");
    state.cancel();
    assert!(matches!(
        worker.join().unwrap(),
        Err(crate::native::error::NativeError::Bridge("Cancelled"))
    ));
    assert!(weak.upgrade().is_none());
}

#[test]
fn reentry_from_a_runtime_thread_fails_instead_of_blocking() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let operation = Operation(Arc::new(OperationState::new()));
    let result = runtime.block_on(async { operation.run(async { Ok(()) }) });
    assert!(matches!(
        result,
        Err(crate::native::error::NativeError::Bridge("ReentrantCall"))
    ));
}

#[cfg(feature = "embed-zkeys")]
#[test]
fn async_calls_fit_small_host_worker_stacks() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path().to_str().unwrap().to_owned();
    std::thread::Builder::new()
        .stack_size(512 * 1024)
        .spawn(move || unsafe {
            let host = MemoryHost::default();
            let paths = storage_paths(&root);
            let store = open_store(paths, &host);
            let mut error = Buffer::empty();
            let mut artifacts = EmbeddedZkArtifactsHandle { id: 0 };
            assert!(walletkit_embedded_zk_artifacts_new(
                &raw mut artifacts,
                &raw mut error
            ));
            let mut source = ZkArtifactSourceHandle { id: 0 };
            assert!(walletkit_embedded_zk_artifacts_as_zk_artifact_source(
                artifacts,
                &raw mut source,
                &raw mut error
            ));
            let mut operation = OperationHandle { id: 0 };
            assert!(walletkit_operation_new(&raw mut operation, &raw mut error));
            let mut authenticator = AuthenticatorHandle { id: 0 };
            assert!(!walletkit_authenticator_init(
                operation,
                ByteSlice::from_slice(&[7; 32]),
                ByteSlice::from_slice(b"not json"),
                source,
                store,
                &raw mut authenticator,
                &raw mut error,
            ));
            assert_eq!(error.take().unwrap()[0], 1, "WalletKitError domain");
            for id in [operation.id, source.id, artifacts.id, store.id, paths.id] {
                walletkit_object_release(id);
            }
        })
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn integrity_sessions_complete_from_host_threads_and_release_signers() {
    let released = Arc::new(AtomicUsize::new(0));
    let provider = integrity_provider(RequestIntegrityProviderCallbacks {
        context: Arc::into_raw(Arc::clone(&released)).cast_mut().cast(),
        prepare: prepare_on_thread,
        release: release_counter,
    });
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let session = runtime.block_on(provider.prepare()).unwrap();
    assert_eq!(session.token, "token");
    assert_eq!(
        session.signer.sign_digest(vec![1; 32]).unwrap(),
        vec![1; 32]
    );
    drop(session);
    assert_eq!(released.load(Ordering::SeqCst), 1, "signer released");
    drop(provider);
    assert_eq!(released.load(Ordering::SeqCst), 2, "provider released");

    let signer_released = Arc::new(AtomicUsize::new(0));
    unsafe {
        walletkit_request_integrity_prepared(
            u64::MAX,
            ByteSlice::from_slice(b"late"),
            0,
            signer(&signer_released),
        );
    }
    assert_eq!(
        signer_released.load(Ordering::SeqCst),
        1,
        "late signer released"
    );

    let failing = integrity_provider(RequestIntegrityProviderCallbacks {
        context: Arc::into_raw(Arc::new(AtomicUsize::new(0)))
            .cast_mut()
            .cast(),
        prepare: fail_preparation,
        release: release_counter,
    });
    assert_eq!(
        runtime.block_on(failing.prepare()).err(),
        Some(RequestIntegrityError::Unavailable)
    );
}

unsafe extern "C" fn prepare_on_thread(context: *mut c_void, completion: u64) {
    let released = unsafe { &*context.cast::<AtomicUsize>() };
    let signer = signer_from(released);
    std::thread::spawn(move || {
        let signer = signer.into_inner();
        unsafe {
            walletkit_request_integrity_prepared(
                completion,
                ByteSlice::from_slice(b"token"),
                1,
                signer,
            );
        }
    });
}

unsafe extern "C" fn fail_preparation(_: *mut c_void, completion: u64) {
    walletkit_request_integrity_failed(completion, 0);
}

struct SendSigner(RequestDigestSignerCallbacks);
// SAFETY: the test context is an `Arc<AtomicUsize>`.
#[allow(
    clippy::non_send_fields_in_send_ty,
    reason = "The context is thread-safe."
)]
unsafe impl Send for SendSigner {}

impl SendSigner {
    const fn into_inner(self) -> RequestDigestSignerCallbacks {
        self.0
    }
}

fn signer_from(counter: &AtomicUsize) -> SendSigner {
    // SAFETY: `counter` lives inside an `Arc` owned by the test.
    let counter = unsafe { Arc::from_raw(std::ptr::from_ref(counter)) };
    let signer = signer(&counter);
    std::mem::forget(counter);
    SendSigner(signer)
}

fn signer(counter: &Arc<AtomicUsize>) -> RequestDigestSignerCallbacks {
    RequestDigestSignerCallbacks {
        context: Arc::into_raw(Arc::clone(counter)).cast_mut().cast(),
        sign_digest: echo_digest,
        release: release_counter,
    }
}

unsafe extern "C" fn echo_digest(
    _: *mut c_void,
    digest: ByteSlice,
    out: *mut Buffer,
) -> bool {
    let digest = unsafe { digest.to_vec() }.unwrap();
    unsafe { out.write(Buffer::from_bytes(digest)) };
    true
}

unsafe extern "C" fn count(context: *mut c_void) {
    unsafe { &*context.cast::<AtomicUsize>() }.fetch_add(1, Ordering::SeqCst);
}

unsafe extern "C" fn release_counter(context: *mut c_void) {
    let counter = unsafe { Arc::from_raw(context.cast::<AtomicUsize>()) };
    counter.fetch_add(1, Ordering::SeqCst);
}

/// Decodes a bridge error (domain 0) and returns its code.
fn bridge_code(error: &mut Buffer) -> String {
    let bytes = std::mem::replace(error, Buffer::empty()).take().unwrap();
    assert_eq!(bytes[0], 0, "bridge domain");
    codec::decode(&bytes[1..]).unwrap()
}

unsafe fn storage_paths(root: &str) -> StoragePathsHandle {
    let mut paths = StoragePathsHandle { id: 0 };
    let mut error = Buffer::empty();
    assert!(unsafe {
        walletkit_storage_paths_from_root(
            ByteSlice::from_slice(root.as_bytes()),
            &raw mut paths,
            &raw mut error,
        )
    });
    paths
}

unsafe fn open_store(
    paths: StoragePathsHandle,
    host: &MemoryHost,
) -> CredentialStoreHandle {
    let mut store = CredentialStoreHandle { id: 0 };
    let mut error = Buffer::empty();
    unsafe {
        assert!(walletkit_credential_store_new_with_components(
            paths,
            host.keystore(),
            host.blob_store(),
            &raw mut store,
            &raw mut error,
        ));
        assert!(walletkit_credential_store_initialize(
            store,
            42,
            100,
            &raw mut error
        ));
    }
    store
}

type Blobs = Mutex<HashMap<String, Vec<u8>>>;
type SealFn = unsafe extern "C" fn(
    *mut c_void,
    ByteSlice,
    ByteSlice,
    *mut Buffer,
    *mut Buffer,
) -> bool;

/// A host whose callback contexts each retain the shared blob map.
#[derive(Default)]
struct MemoryHost {
    blobs: Arc<Blobs>,
}

impl MemoryHost {
    fn context(&self) -> *mut c_void {
        Arc::into_raw(Arc::clone(&self.blobs)).cast_mut().cast()
    }

    fn keystore(&self) -> DeviceKeystoreCallbacks {
        DeviceKeystoreCallbacks {
            context: self.context(),
            seal: concat_seal,
            open_sealed: strip_open,
            release,
        }
    }

    fn blob_store(&self) -> AtomicBlobStoreCallbacks {
        AtomicBlobStoreCallbacks {
            context: self.context(),
            read,
            write_atomic,
            delete_blob: delete,
            release,
        }
    }
}

unsafe fn blobs<'a>(context: *mut c_void) -> &'a Blobs {
    unsafe { &*context.cast::<Blobs>() }
}

unsafe fn path(slice: ByteSlice) -> String {
    unsafe { slice.string() }.unwrap()
}

unsafe extern "C" fn concat_seal(
    _: *mut c_void,
    associated_data: ByteSlice,
    plaintext: ByteSlice,
    out: *mut Buffer,
    _: *mut Buffer,
) -> bool {
    let sealed = unsafe {
        [associated_data.bytes().unwrap(), plaintext.bytes().unwrap()].concat()
    };
    unsafe { out.write(Buffer::from_bytes(sealed)) };
    true
}

unsafe extern "C" fn strip_open(
    _: *mut c_void,
    associated_data: ByteSlice,
    ciphertext: ByteSlice,
    out: *mut Buffer,
    _: *mut Buffer,
) -> bool {
    let opened = unsafe { ciphertext.bytes() }.unwrap()[associated_data.len..].to_vec();
    unsafe { out.write(Buffer::from_bytes(opened)) };
    true
}

unsafe extern "C" fn failing_seal(
    _: *mut c_void,
    _: ByteSlice,
    _: ByteSlice,
    _: *mut Buffer,
    out_error: *mut Buffer,
) -> bool {
    let error = codec::encode(walletkit_core::storage::StorageError::Keystore(
        "denied".into(),
    ))
    .unwrap()
    .claim();
    unsafe { out_error.write(Buffer::from_bytes(error)) };
    false
}

/// Reports success without writing a sealed value.
const unsafe extern "C" fn empty_seal(
    _: *mut c_void,
    _: ByteSlice,
    _: ByteSlice,
    _: *mut Buffer,
    _: *mut Buffer,
) -> bool {
    true
}

const unsafe extern "C" fn opaque_seal(
    _: *mut c_void,
    _: ByteSlice,
    _: ByteSlice,
    _: *mut Buffer,
    _: *mut Buffer,
) -> bool {
    false
}

unsafe extern "C" fn read(
    context: *mut c_void,
    name: ByteSlice,
    out: *mut Buffer,
    _: *mut Buffer,
) -> bool {
    let blob = unsafe { blobs(context) }
        .lock()
        .unwrap()
        .get(&unsafe { path(name) })
        .cloned();
    if let Some(blob) = blob {
        unsafe { out.write(Buffer::from_bytes(blob)) };
    }
    true
}

unsafe extern "C" fn write_atomic(
    context: *mut c_void,
    name: ByteSlice,
    contents: ByteSlice,
    _: *mut Buffer,
) -> bool {
    let contents = unsafe { contents.to_vec() }.unwrap();
    unsafe { blobs(context) }
        .lock()
        .unwrap()
        .insert(unsafe { path(name) }, contents);
    true
}

unsafe extern "C" fn delete(
    context: *mut c_void,
    name: ByteSlice,
    _: *mut Buffer,
) -> bool {
    unsafe { blobs(context) }
        .lock()
        .unwrap()
        .remove(&unsafe { path(name) });
    true
}

unsafe extern "C" fn release(context: *mut c_void) {
    drop(unsafe { Arc::from_raw(context.cast::<Blobs>()) });
}
