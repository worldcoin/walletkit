//! Typed C ABI for Swift and other C hosts; cbindgen generates `walletkit_coreFFI.h`.
//!
//! Conventions:
//! - Fallible functions return `true` on success and write their result to `out`. On
//!   failure they return `false` and write an encoded error (see `native::error`) to
//!   `out_error`, which the caller frees with `walletkit_buffer_free`. `out` and
//!   `out_error` must be valid for writes.
//! - Inputs are borrowed for the duration of the call. Strings are UTF-8 and not
//!   NUL-terminated. Optional strings and bytes are nullable pointers to a slice;
//!   optional integers are nullable pointers; optional enumerations are -1 when absent.
//! - Returned buffers are owned by the caller. An optional buffer result is absent when
//!   its `data` is null; an empty value has non-null `data`.
//! - Handles are typed `{ id }` structs over the shared registry; zero is never valid.
//!   Release them with `walletkit_object_release`. A running call keeps its own
//!   references, so releasing during a call is safe. A returned handle, including one
//!   inside an encoded result, is owned by the caller.
//! - Callback tables transfer one retain of `context` to Rust, released exactly once
//!   through `release`, including when the call fails. Callbacks run on arbitrary
//!   threads; their output buffers must come from `walletkit_buffer_copy`.

mod authenticator;
mod callbacks;
mod flamingo;
mod identity;
#[cfg(feature = "issuers")]
mod issuers;
mod storage;
#[cfg(all(test, feature = "v3"))]
mod tests;
#[cfg(feature = "v3")]
mod v3;

use super::{
    codec::{self, Binary, Decode, Encode},
    error::{NativeError, Result},
    operation::{Operation, OperationState},
    ops,
    registry::{self, NativeObject},
    values::Ordinal,
};
use std::{panic::AssertUnwindSafe, sync::Arc};
use zeroize::Zeroize;

/// Bytes owned by Rust. Only `walletkit_buffer_free` may release them.
#[repr(C)]
pub struct Buffer {
    /// First byte, or null for an absent value.
    pub data: *mut u8,
    /// Length in bytes.
    pub len: usize,
}

impl Buffer {
    /// Moves `bytes` into an exactly sized allocation without leaving an unzeroed copy.
    fn from_bytes(mut bytes: Vec<u8>) -> Self {
        let bytes: Box<[u8]> = if bytes.capacity() == bytes.len() {
            bytes.into_boxed_slice()
        } else {
            let exact = Box::from(bytes.as_slice());
            bytes.zeroize();
            exact
        };
        let len = bytes.len();
        Self {
            data: Box::into_raw(bytes).cast::<u8>(),
            len,
        }
    }

    const fn empty() -> Self {
        Self {
            data: std::ptr::null_mut(),
            len: 0,
        }
    }

    /// Reclaims a buffer allocated by this library, such as host callback output.
    fn take(self) -> Option<Vec<u8>> {
        if self.data.is_null() {
            return None;
        }
        // SAFETY: buffers originate from Box<[u8]> in this library and are taken once.
        Some(
            unsafe {
                Box::from_raw(std::ptr::slice_from_raw_parts_mut(self.data, self.len))
            }
            .into_vec(),
        )
    }
}

/// Borrowed bytes. `data` may be null only when `len` is zero.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ByteSlice {
    /// First byte.
    pub data: *const u8,
    /// Length in bytes.
    pub len: usize,
}

impl ByteSlice {
    const fn from_slice(bytes: &[u8]) -> Self {
        Self {
            data: bytes.as_ptr(),
            len: bytes.len(),
        }
    }

    /// # Safety
    /// `data` must be readable for `len` bytes for the lifetime of the result.
    const unsafe fn bytes<'a>(self) -> Result<&'a [u8]> {
        if self.len == 0 {
            return Ok(&[]);
        }
        if self.data.is_null() {
            return Err(NativeError::invalid_input());
        }
        // SAFETY: guaranteed by the caller.
        Ok(unsafe { std::slice::from_raw_parts(self.data, self.len) })
    }

    /// # Safety
    /// As for [`Self::bytes`].
    unsafe fn to_vec(self) -> Result<Vec<u8>> {
        // SAFETY: forwarded.
        Ok(unsafe { self.bytes() }?.to_vec())
    }

    /// # Safety
    /// As for [`Self::bytes`].
    unsafe fn string(self) -> Result<String> {
        // SAFETY: forwarded.
        String::from_utf8(unsafe { self.to_vec() }?)
            .map_err(|_| NativeError::invalid_input())
    }

    /// Decodes a record, list, or map in the binary encoding.
    ///
    /// # Safety
    /// As for [`Self::bytes`].
    unsafe fn decode<T: Decode>(self) -> Result<Binary<T>> {
        // SAFETY: forwarded.
        codec::decode(unsafe { self.bytes() }?).map(Binary)
    }
}

/// # Safety
/// `slice` must be null or point to a valid slice whose bytes are readable.
unsafe fn optional_bytes(slice: *const ByteSlice) -> Result<Option<Vec<u8>>> {
    // SAFETY: guaranteed by the caller.
    unsafe { slice.as_ref() }
        .map(|slice| unsafe { slice.to_vec() })
        .transpose()
}

/// # Safety
/// As for [`optional_bytes`].
unsafe fn optional_string(slice: *const ByteSlice) -> Result<Option<String>> {
    // SAFETY: guaranteed by the caller.
    unsafe { slice.as_ref() }
        .map(|slice| unsafe { slice.string() })
        .transpose()
}

/// # Safety
/// `value` must be null or readable.
const unsafe fn optional_u64(value: *const u64) -> Option<u64> {
    // SAFETY: guaranteed by the caller.
    unsafe { value.as_ref() }.copied()
}

fn ordinal<T: Ordinal>(value: u8) -> Result<T> {
    T::from_ordinal(value.into()).ok_or_else(NativeError::invalid_input)
}

fn optional_ordinal<T: Ordinal>(value: i32) -> Result<Option<T>> {
    if value == -1 {
        return Ok(None);
    }
    T::from_ordinal(value.into())
        .map(Some)
        .ok_or_else(NativeError::invalid_input)
}

/// An unsigned 256-bit integer as 32 big-endian bytes.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Uint256 {
    /// Big-endian bytes.
    pub bytes: [u8; 32],
}

impl From<Uint256> for walletkit_core::Uint256 {
    fn from(value: Uint256) -> Self {
        super::values::uint256(value.bytes)
    }
}

/// A `FieldElement`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FieldElementHandle {
    /// Registry ID.
    pub id: u64,
}

/// A `Credential`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CredentialHandle {
    /// Registry ID.
    pub id: u64,
}

/// An `OwnershipProof`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct OwnershipProofHandle {
    /// Registry ID.
    pub id: u64,
}

/// A `ProofRequest`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProofRequestHandle {
    /// Registry ID.
    pub id: u64,
}

/// A `ProofResponse`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProofResponseHandle {
    /// Registry ID.
    pub id: u64,
}

/// A `UserAgent`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct UserAgentHandle {
    /// Registry ID.
    pub id: u64,
}

/// A `UserAgentBuilder`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct UserAgentBuilderHandle {
    /// Registry ID.
    pub id: u64,
}

/// A `StoragePaths`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct StoragePathsHandle {
    /// Registry ID.
    pub id: u64,
}

/// A `CredentialStore`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CredentialStoreHandle {
    /// Registry ID.
    pub id: u64,
}

/// An `Authenticator`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AuthenticatorHandle {
    /// Registry ID.
    pub id: u64,
}

/// An `InitializingAuthenticator`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct InitializingAuthenticatorHandle {
    /// Registry ID.
    pub id: u64,
}

/// A `WalletKitZkArtifactSource`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ZkArtifactSourceHandle {
    /// Registry ID.
    pub id: u64,
}

/// An `EmbeddedZkArtifacts`.
#[cfg(feature = "embed-zkeys")]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct EmbeddedZkArtifactsHandle {
    /// Registry ID.
    pub id: u64,
}

/// A `CachingZkArtifacts`.
#[cfg(feature = "embed-zkeys")]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CachingZkArtifactsHandle {
    /// Registry ID.
    pub id: u64,
}

/// A `FlamingoMatcher`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FlamingoMatcherHandle {
    /// Registry ID.
    pub id: u64,
}

/// A `VerifiedMatchToken`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct VerifiedMatchTokenHandle {
    /// Registry ID.
    pub id: u64,
}

/// A `TfhNfcIssuer`.
#[cfg(feature = "issuers")]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TfhNfcIssuerHandle {
    /// Registry ID.
    pub id: u64,
}

/// A `RecoveryBindingManager`.
#[cfg(feature = "issuers")]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RecoveryBindingManagerHandle {
    /// Registry ID.
    pub id: u64,
}

/// An `AddressBook`.
#[cfg(feature = "v3")]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AddressBookHandle {
    /// Registry ID.
    pub id: u64,
}

/// A `WorldId`.
#[cfg(feature = "v3")]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct WorldIdHandle {
    /// Registry ID.
    pub id: u64,
}

/// A `ProofContext`.
#[cfg(feature = "v3")]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProofContextHandle {
    /// Registry ID.
    pub id: u64,
}

/// A `ProofOutput`.
#[cfg(feature = "v3")]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProofOutputHandle {
    /// Registry ID.
    pub id: u64,
}

/// A `MerkleTreeProof`.
#[cfg(feature = "v3")]
#[repr(C)]
#[derive(Clone, Copy)]
pub struct MerkleTreeProofHandle {
    /// Registry ID.
    pub id: u64,
}

/// A cancellation token for one async call.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct OperationHandle {
    /// Registry ID.
    pub id: u64,
}

/// A typed handle struct and the object it refers to.
trait Handle: Copy {
    type Target: NativeObject + ?Sized;
    fn id(self) -> u64;
    fn from_id(id: u64) -> Self;

    fn get(self) -> Result<Arc<Self::Target>> {
        registry::get(self.id())
    }
}

macro_rules! handles {
    ($($(#[$meta:meta])* $handle:ident => $target:ty),* $(,)?) => {$(
        $(#[$meta])*
        impl Handle for $handle {
            type Target = $target;
            fn id(self) -> u64 {
                self.id
            }
            fn from_id(id: u64) -> Self {
                Self { id }
            }
        }

        $(#[$meta])*
        impl IntoC for Arc<$target> {
            type Raw = $handle;
            fn into_c(self) -> Result<$handle> {
                registry::insert(self).map($handle::from_id)
            }
        }

        $(#[$meta])*
        impl IntoC for Option<Arc<$target>> {
            type Raw = $handle;
            fn into_c(self) -> Result<$handle> {
                self.map_or(Ok($handle::from_id(0)), IntoC::into_c)
            }
        }
    )*};
}

handles! {
    FieldElementHandle => walletkit_core::FieldElement,
    CredentialHandle => walletkit_core::Credential,
    OwnershipProofHandle => walletkit_core::OwnershipProof,
    ProofRequestHandle => walletkit_core::requests::ProofRequest,
    ProofResponseHandle => walletkit_core::requests::ProofResponse,
    UserAgentHandle => walletkit_core::user_agent::UserAgent,
    UserAgentBuilderHandle => walletkit_core::user_agent::UserAgentBuilder,
    StoragePathsHandle => walletkit_core::storage::paths::StoragePaths,
    CredentialStoreHandle => walletkit_core::storage::credential_storage::CredentialStore,
    AuthenticatorHandle => walletkit_core::authenticator::Authenticator,
    InitializingAuthenticatorHandle => walletkit_core::authenticator::InitializingAuthenticator,
    ZkArtifactSourceHandle => dyn walletkit_core::authenticator::artifacts::WalletKitZkArtifactSource,
    #[cfg(feature = "embed-zkeys")]
    EmbeddedZkArtifactsHandle => walletkit_core::authenticator::artifacts::embedded::EmbeddedZkArtifacts,
    #[cfg(feature = "embed-zkeys")]
    CachingZkArtifactsHandle => walletkit_core::authenticator::artifacts::caching::CachingZkArtifacts,
    FlamingoMatcherHandle => walletkit_core::flamingo::FlamingoMatcher,
    VerifiedMatchTokenHandle => walletkit_core::flamingo::VerifiedMatchToken,
    #[cfg(feature = "issuers")]
    TfhNfcIssuerHandle => walletkit_core::issuers::TfhNfcIssuer,
    #[cfg(feature = "issuers")]
    RecoveryBindingManagerHandle => walletkit_core::issuers::RecoveryBindingManager,
    #[cfg(feature = "v3")]
    AddressBookHandle => walletkit_core::v3::common_apps::AddressBook,
    #[cfg(feature = "v3")]
    WorldIdHandle => walletkit_core::v3::world_id::WorldId,
    #[cfg(feature = "v3")]
    ProofContextHandle => walletkit_core::v3::proof::ProofContext,
    #[cfg(feature = "v3")]
    ProofOutputHandle => walletkit_core::v3::proof::ProofOutput,
    #[cfg(feature = "v3")]
    MerkleTreeProofHandle => walletkit_core::v3::MerkleTreeProof,
    OperationHandle => OperationState,
}

impl OperationHandle {
    fn operation(self) -> Result<Operation> {
        self.get().map(Operation)
    }
}

/// Converts an operation result into the value written to `out`.
trait IntoC {
    type Raw;
    fn into_c(self) -> Result<Self::Raw>;
}

macro_rules! scalars {
    ($($ty:ty),*) => {$(
        impl IntoC for $ty {
            type Raw = $ty;
            fn into_c(self) -> Result<$ty> {
                Ok(self)
            }
        }
    )*};
}
scalars!(u64, u32, u8, bool, f32);

impl<T: Ordinal> IntoC for T {
    type Raw = u8;
    fn into_c(self) -> Result<u8> {
        Ok(self.ordinal())
    }
}

impl IntoC for String {
    type Raw = Buffer;
    fn into_c(self) -> Result<Buffer> {
        Ok(Buffer::from_bytes(self.into_bytes()))
    }
}

impl IntoC for Option<String> {
    type Raw = Buffer;
    fn into_c(self) -> Result<Buffer> {
        self.map_or(Ok(Buffer::empty()), IntoC::into_c)
    }
}

impl IntoC for Vec<u8> {
    type Raw = Buffer;
    fn into_c(self) -> Result<Buffer> {
        Ok(Buffer::from_bytes(self))
    }
}

impl IntoC for walletkit_core::Uint256 {
    type Raw = Uint256;
    fn into_c(self) -> Result<Uint256> {
        Ok(Uint256 {
            bytes: self.0.to_be_bytes::<32>(),
        })
    }
}

impl<T: Encode> IntoC for Binary<T> {
    type Raw = Buffer;
    fn into_c(self) -> Result<Buffer> {
        Ok(Buffer::from_bytes(codec::encode(self.0)?.claim()))
    }
}

/// Runs `body`, writing its result to `out` or its error to `out_error`.
///
/// # Safety
/// `out` and `out_error` must be null or valid for writes.
unsafe fn complete<R: IntoC>(
    out: *mut R::Raw,
    out_error: *mut Buffer,
    body: impl FnOnce() -> Result<R>,
) -> bool {
    if out.is_null() || out_error.is_null() {
        return false;
    }
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| body()?.into_c()))
        .unwrap_or_else(|_| Err(NativeError::bridge("Panic")));
    match result {
        Ok(value) => {
            // SAFETY: checked non-null; validity guaranteed by the caller.
            unsafe { out.write(value) };
            true
        }
        Err(error) => {
            // SAFETY: checked non-null; validity guaranteed by the caller.
            unsafe { out_error.write(Buffer::from_bytes(error.encode())) };
            false
        }
    }
}

/// [`complete`] for functions without a result.
///
/// # Safety
/// `out_error` must be null or valid for writes.
unsafe fn complete_unit(
    out_error: *mut Buffer,
    body: impl FnOnce() -> Result<()>,
) -> bool {
    let mut unit = 0_u8;
    // SAFETY: forwarded from the caller; `unit` is a valid local.
    unsafe { complete(&raw mut unit, out_error, || body().map(|()| 0_u8)) }
}

/// The native interface version; the SDK refuses to run against another version.
#[no_mangle]
pub const extern "C" fn walletkit_abi_version() -> u32 {
    ops::abi_version()
}

/// Creates a cancellation token for one async call. Release it with
/// `walletkit_object_release` once the call has returned.
///
/// # Safety
/// `out` and `out_error` must be valid for writes.
#[no_mangle]
pub unsafe extern "C" fn walletkit_operation_new(
    out: *mut OperationHandle,
    out_error: *mut Buffer,
) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe { complete(out, out_error, || Ok(ops::operation_new())) }
}

/// Cancels an operation before or during its call. Unknown handles are ignored.
#[no_mangle]
pub extern "C" fn walletkit_operation_cancel(operation: OperationHandle) {
    ops::operation_cancel(operation.id);
}

/// Releases a handle of any type. Idempotent; running calls keep their own references.
#[no_mangle]
pub extern "C" fn walletkit_object_release(id: u64) {
    ops::object_release(id);
}

/// Copies host bytes into a buffer that Rust can take ownership of, such as callback
/// output. Returns an empty buffer when `data` is null.
///
/// # Safety
/// `data` must be readable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn walletkit_buffer_copy(data: *const u8, len: usize) -> Buffer {
    // SAFETY: guaranteed by the caller.
    unsafe { ByteSlice { data, len }.to_vec() }
        .map_or_else(|_| Buffer::empty(), Buffer::from_bytes)
}

/// Zeroes and releases a buffer returned by this library. Null buffers are ignored.
///
/// # Safety
/// `buffer` must come from this library and must not be used afterwards.
#[no_mangle]
pub unsafe extern "C" fn walletkit_buffer_free(buffer: Buffer) {
    if let Some(mut bytes) = buffer.take() {
        bytes.zeroize();
    }
}
