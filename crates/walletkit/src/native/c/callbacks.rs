//! Host callback tables. Each table carries a `context` that Rust retains once and
//! releases exactly once through `release`; functions run on arbitrary threads.

use super::{ordinal, Buffer, ByteSlice};
use crate::native::{codec, integrity};
use std::{ffi::c_void, sync::Arc};
use walletkit_core::{
    flamingo::{
        RequestDigestSigner, RequestIntegrityError, RequestIntegrityPlatform,
        RequestIntegrityProvider,
    },
    logger::{LogLevel, Logger},
    storage::{
        ActivityChangedListener, AtomicBlobStore, DeviceKeystore, StorageError,
        StorageResult, VaultChangedListener,
    },
};
use zeroize::Zeroizing;

/// A device keystore. On failure a function returns `false` and may write an encoded
/// `StorageError` to `out_error`; any other failure is reported as `HostFailure`.
#[repr(C)]
pub struct DeviceKeystoreCallbacks {
    /// Host state passed to every function.
    pub context: *mut c_void,
    /// Seals `plaintext` bound to `associated_data`.
    pub seal: unsafe extern "C" fn(
        context: *mut c_void,
        associated_data: ByteSlice,
        plaintext: ByteSlice,
        out: *mut Buffer,
        out_error: *mut Buffer,
    ) -> bool,
    /// Opens `ciphertext` bound to `associated_data`.
    pub open_sealed: unsafe extern "C" fn(
        context: *mut c_void,
        associated_data: ByteSlice,
        ciphertext: ByteSlice,
        out: *mut Buffer,
        out_error: *mut Buffer,
    ) -> bool,
    /// Releases `context`. Called exactly once.
    pub release: unsafe extern "C" fn(context: *mut c_void),
}

/// Atomic blob storage. Same error contract as [`DeviceKeystoreCallbacks`].
#[repr(C)]
pub struct AtomicBlobStoreCallbacks {
    /// Host state passed to every function.
    pub context: *mut c_void,
    /// Reads a blob, leaving `out` null when it does not exist.
    pub read: unsafe extern "C" fn(
        context: *mut c_void,
        path: ByteSlice,
        out: *mut Buffer,
        out_error: *mut Buffer,
    ) -> bool,
    /// Atomically replaces a blob.
    pub write_atomic: unsafe extern "C" fn(
        context: *mut c_void,
        path: ByteSlice,
        bytes: ByteSlice,
        out_error: *mut Buffer,
    ) -> bool,
    /// Deletes a blob.
    pub delete_blob: unsafe extern "C" fn(
        context: *mut c_void,
        path: ByteSlice,
        out_error: *mut Buffer,
    ) -> bool,
    /// Releases `context`. Called exactly once.
    pub release: unsafe extern "C" fn(context: *mut c_void),
}

/// A log sink. `level` is the `LogLevel` ordinal; messages are UTF-8.
#[repr(C)]
pub struct LoggerCallbacks {
    /// Host state passed to every function.
    pub context: *mut c_void,
    /// Receives one log message.
    pub log: unsafe extern "C" fn(context: *mut c_void, level: u8, message: ByteSlice),
    /// Releases `context`. Called exactly once.
    pub release: unsafe extern "C" fn(context: *mut c_void),
}

/// A listener notified after vault changes.
#[repr(C)]
pub struct VaultChangedListenerCallbacks {
    /// Host state passed to every function.
    pub context: *mut c_void,
    /// Called after the vault changed.
    pub on_vault_changed: unsafe extern "C" fn(context: *mut c_void),
    /// Releases `context`. Called exactly once.
    pub release: unsafe extern "C" fn(context: *mut c_void),
}

/// A listener notified after activity changes.
#[repr(C)]
pub struct ActivityChangedListenerCallbacks {
    /// Host state passed to every function.
    pub context: *mut c_void,
    /// Called after the activity history changed.
    pub on_activity_changed: unsafe extern "C" fn(context: *mut c_void),
    /// Releases `context`. Called exactly once.
    pub release: unsafe extern "C" fn(context: *mut c_void),
}

/// Supplies request-integrity sessions for attested Flamingo connections.
#[repr(C)]
pub struct RequestIntegrityProviderCallbacks {
    /// Host state passed to every function.
    pub context: *mut c_void,
    /// Starts preparing a session. The host must later call exactly one of
    /// `walletkit_request_integrity_prepared` or `walletkit_request_integrity_failed`
    /// with `completion`, from any thread.
    pub prepare: unsafe extern "C" fn(context: *mut c_void, completion: u64),
    /// Releases `context`. Called exactly once.
    pub release: unsafe extern "C" fn(context: *mut c_void),
}

/// Signs request digests with the key certified by a session token.
#[repr(C)]
pub struct RequestDigestSignerCallbacks {
    /// Host state passed to every function.
    pub context: *mut c_void,
    /// Signs exactly 32 bytes, writing the platform signature to `out`.
    pub sign_digest: unsafe extern "C" fn(
        context: *mut c_void,
        client_data_hash: ByteSlice,
        out: *mut Buffer,
    ) -> bool,
    /// Releases `context`. Called exactly once.
    pub release: unsafe extern "C" fn(context: *mut c_void),
}

/// A callback table owned by Rust.
struct Host<T: Table>(T);

trait Table {
    fn release(&self);
}

macro_rules! tables {
    ($($table:ident),* $(,)?) => {$(
        impl Table for $table {
            fn release(&self) {
                // SAFETY: construction transferred exactly one context retain.
                unsafe { (self.release)(self.context) };
            }
        }
    )*};
}

tables!(
    DeviceKeystoreCallbacks,
    AtomicBlobStoreCallbacks,
    LoggerCallbacks,
    VaultChangedListenerCallbacks,
    ActivityChangedListenerCallbacks,
    RequestIntegrityProviderCallbacks,
    RequestDigestSignerCallbacks,
);

impl<T: Table> Drop for Host<T> {
    fn drop(&mut self) {
        self.0.release();
    }
}

// SAFETY: the callback contract requires thread-safe host functions and context.
#[allow(
    clippy::non_send_fields_in_send_ty,
    reason = "The host contract makes the context pointer thread-safe."
)]
unsafe impl<T: Table> Send for Host<T> {}
// SAFETY: as above.
unsafe impl<T: Table> Sync for Host<T> {}

/// Takes ownership of a keystore table.
pub fn keystore(table: DeviceKeystoreCallbacks) -> Arc<dyn DeviceKeystore> {
    Arc::new(Host(table))
}

/// Takes ownership of a blob store table.
pub fn blob_store(table: AtomicBlobStoreCallbacks) -> Arc<dyn AtomicBlobStore> {
    Arc::new(Host(table))
}

/// Takes ownership of a logger table.
pub fn logger(table: LoggerCallbacks) -> Arc<dyn Logger> {
    Arc::new(Host(table))
}

/// Takes ownership of a vault listener table.
pub fn vault_listener(
    table: VaultChangedListenerCallbacks,
) -> Arc<dyn VaultChangedListener> {
    Arc::new(Host(table))
}

/// Takes ownership of an activity listener table.
pub fn activity_listener(
    table: ActivityChangedListenerCallbacks,
) -> Arc<dyn ActivityChangedListener> {
    Arc::new(Host(table))
}

/// Takes ownership of an integrity provider table.
pub fn integrity_provider(
    table: RequestIntegrityProviderCallbacks,
) -> Arc<dyn RequestIntegrityProvider> {
    let host = Host(table);
    Arc::new(integrity::HostProvider::new(move |completion| {
        host.prepare(completion);
        Ok(())
    }))
}

impl Host<RequestIntegrityProviderCallbacks> {
    fn prepare(&self, completion: u64) {
        // SAFETY: the host contract.
        unsafe { (self.0.prepare)(self.0.context, completion) };
    }
}

impl DeviceKeystore for Host<DeviceKeystoreCallbacks> {
    fn seal(
        &self,
        associated_data: Vec<u8>,
        plaintext: Vec<u8>,
    ) -> StorageResult<Vec<u8>> {
        let plaintext = Zeroizing::new(plaintext);
        storage_bytes(|out, out_error| {
            // SAFETY: the host contract; inputs outlive the call.
            unsafe {
                (self.0.seal)(
                    self.0.context,
                    ByteSlice::from_slice(&associated_data),
                    ByteSlice::from_slice(&plaintext),
                    out,
                    out_error,
                )
            }
        })
        .and_then(required)
    }

    fn open_sealed(
        &self,
        associated_data: Vec<u8>,
        ciphertext: Vec<u8>,
    ) -> StorageResult<Vec<u8>> {
        storage_bytes(|out, out_error| {
            // SAFETY: the host contract; inputs outlive the call.
            unsafe {
                (self.0.open_sealed)(
                    self.0.context,
                    ByteSlice::from_slice(&associated_data),
                    ByteSlice::from_slice(&ciphertext),
                    out,
                    out_error,
                )
            }
        })
        .and_then(required)
    }
}

impl AtomicBlobStore for Host<AtomicBlobStoreCallbacks> {
    fn read(&self, path: String) -> StorageResult<Option<Vec<u8>>> {
        storage_bytes(|out, out_error| {
            // SAFETY: the host contract; inputs outlive the call.
            unsafe {
                (self.0.read)(
                    self.0.context,
                    ByteSlice::from_slice(path.as_bytes()),
                    out,
                    out_error,
                )
            }
        })
    }

    fn write_atomic(&self, path: String, bytes: Vec<u8>) -> StorageResult<()> {
        storage_unit(|out_error| {
            // SAFETY: the host contract; inputs outlive the call.
            unsafe {
                (self.0.write_atomic)(
                    self.0.context,
                    ByteSlice::from_slice(path.as_bytes()),
                    ByteSlice::from_slice(&bytes),
                    out_error,
                )
            }
        })
    }

    fn delete(&self, path: String) -> StorageResult<()> {
        storage_unit(|out_error| {
            // SAFETY: the host contract; inputs outlive the call.
            unsafe {
                (self.0.delete_blob)(
                    self.0.context,
                    ByteSlice::from_slice(path.as_bytes()),
                    out_error,
                )
            }
        })
    }
}

impl Logger for Host<LoggerCallbacks> {
    fn log(&self, level: LogLevel, message: String) {
        use crate::native::values::Ordinal as _;
        // SAFETY: the host contract; inputs outlive the call.
        unsafe {
            (self.0.log)(
                self.0.context,
                level.ordinal(),
                ByteSlice::from_slice(message.as_bytes()),
            );
        }
    }
}

impl VaultChangedListener for Host<VaultChangedListenerCallbacks> {
    fn on_vault_changed(&self) {
        // SAFETY: the host contract.
        unsafe { (self.0.on_vault_changed)(self.0.context) };
    }
}

impl ActivityChangedListener for Host<ActivityChangedListenerCallbacks> {
    fn on_activity_changed(&self) {
        // SAFETY: the host contract.
        unsafe { (self.0.on_activity_changed)(self.0.context) };
    }
}

impl RequestDigestSigner for Host<RequestDigestSignerCallbacks> {
    fn sign_digest(
        &self,
        client_data_hash: Vec<u8>,
    ) -> Result<Vec<u8>, RequestIntegrityError> {
        let mut out = Buffer::empty();
        // SAFETY: the host contract; inputs outlive the call.
        let signed = unsafe {
            (self.0.sign_digest)(
                self.0.context,
                ByteSlice::from_slice(&client_data_hash),
                &raw mut out,
            )
        };
        let signature = out.take();
        signature
            .filter(|_| signed)
            .ok_or(RequestIntegrityError::SigningFailed)
    }
}

fn storage_bytes(
    call: impl FnOnce(*mut Buffer, *mut Buffer) -> bool,
) -> StorageResult<Option<Vec<u8>>> {
    let mut out = Buffer::empty();
    let mut error = Buffer::empty();
    let succeeded = call(&raw mut out, &raw mut error);
    let out = out.take();
    if succeeded {
        drop(error.take());
        Ok(out)
    } else {
        // Output written before a failure may hold plaintext.
        drop(out.map(Zeroizing::new));
        Err(storage_error(error))
    }
}

/// A keystore must return bytes; an empty result would be persisted as a sealed value.
fn required(bytes: Option<Vec<u8>>) -> StorageResult<Vec<u8>> {
    bytes.ok_or_else(|| StorageError::Callback("MissingResult".into()))
}

fn storage_unit(call: impl FnOnce(*mut Buffer) -> bool) -> StorageResult<()> {
    let mut error = Buffer::empty();
    if call(&raw mut error) {
        drop(error.take());
        Ok(())
    } else {
        Err(storage_error(error))
    }
}

/// Explicit host `StorageError`s keep their variant; anything else is `HostFailure`.
fn storage_error(error: Buffer) -> StorageError {
    error
        .take()
        .and_then(|bytes| codec::decode(&bytes).ok())
        .unwrap_or_else(|| StorageError::Callback("HostFailure".into()))
}

/// Completes a pending integrity preparation with the host's session. Consumes
/// `signer`, including when `completion` has expired or the input is invalid.
///
/// # Safety
/// `token` must be readable; `signer` must satisfy its table contract.
#[no_mangle]
pub unsafe extern "C" fn walletkit_request_integrity_prepared(
    completion: u64,
    token: ByteSlice,
    platform: u8,
    signer: RequestDigestSignerCallbacks,
) {
    let signer: Arc<dyn RequestDigestSigner> = Arc::new(Host(signer));
    // SAFETY: guaranteed by the caller.
    let token = unsafe { token.string() };
    let platform = ordinal::<RequestIntegrityPlatform>(platform);
    let result = match (token, platform) {
        (Ok(token), Ok(platform)) => Ok((token, platform, signer)),
        _ => Err(RequestIntegrityError::InvalidSession),
    };
    integrity::complete(completion, result);
}

/// Completes a pending integrity preparation with the ordinal of a
/// `RequestIntegrityError`; unknown ordinals report `CallbackFailed`.
#[no_mangle]
pub extern "C" fn walletkit_request_integrity_failed(completion: u64, error: u8) {
    let error = ordinal::<RequestIntegrityError>(error)
        .unwrap_or(RequestIntegrityError::CallbackFailed);
    integrity::complete(completion, Err(error));
}
