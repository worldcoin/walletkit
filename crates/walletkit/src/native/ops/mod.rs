//! Native operations: one plain Rust function per SDK method.
//!
//! Each function is the whole JNI binding: `#[jni_export]` adds the `extern "system"`
//! symbol `Java_org_world_walletkit_NativeBridge_<lowerCamelCase name>`. The C ABI
//! wraps the same function in `walletkit_<name>` (see `native::c`).
//!
//! Parameter and result types choose the representation on both platforms:
//!
//! | Rust type | Kotlin / JNI | C |
//! |---|---|---|
//! | `u64`, `u32`, `bool` | `Long`, `Int`, `Boolean` | same-width integer, `bool` |
//! | `Option<u64>` | `Long?` | nullable pointer |
//! | fieldless enum | `Int` ordinal | `uint8_t` ordinal (`int32_t`, -1 for `None`) |
//! | `String`, `Vec<u8>` | `String`, `ByteArray` | `WalletKitByteSlice` in, `WalletKitBuffer` out |
//! | `Uint256` | 32-byte `ByteArray` | `WalletKitUint256` |
//! | `Arc<T>` resource | `NativeHandle` in, `Long` out | typed handle struct |
//! | `Binary<T>` record, list, map | `ByteArray` | `WalletKitByteSlice` / `WalletKitBuffer` |
//! | `Arc<dyn Callback>` | Kotlin interface object | callback table |
//! | `Operation` | `Long` from `operationNew` | `WalletKitOperationHandle` |

#![allow(
    clippy::needless_pass_by_value,
    reason = "Arguments arrive as owned values from both JNI and C conversions."
)]

pub mod authenticator;
pub mod identity;
pub mod storage;

use super::{
    operation::OperationState,
    registry::{self, NativeObject},
};
use std::sync::Arc;
#[cfg(feature = "jni")]
use walletkit_jni_macros::jni_export;

/// Secret input bytes, such as seeds, zeroed when dropped on any path, including when a
/// later argument is invalid or the operation is cancelled before it starts.
pub type Secret = zeroize::Zeroizing<Vec<u8>>;

/// Hands secret bytes to the core, which takes ownership and zeroes them.
pub fn reveal(mut secret: Secret) -> Vec<u8> {
    std::mem::take(&mut *secret)
}

/// Version of the native interface. The SDKs refuse to run against another version.
pub const ABI_VERSION: u32 = 2;

macro_rules! objects {
    ($($(#[$meta:meta])* $ty:ty),* $(,)?) => {$(
        $(#[$meta])*
        impl NativeObject for $ty {}
    )*};
}

objects! {
    walletkit_core::FieldElement,
    walletkit_core::Credential,
    walletkit_core::OwnershipProof,
    walletkit_core::requests::ProofRequest,
    walletkit_core::requests::ProofResponse,
    walletkit_core::user_agent::UserAgent,
    walletkit_core::user_agent::UserAgentBuilder,
    walletkit_core::storage::paths::StoragePaths,
    walletkit_core::storage::credential_storage::CredentialStore,
    walletkit_core::authenticator::Authenticator,
    walletkit_core::authenticator::InitializingAuthenticator,
    dyn walletkit_core::authenticator::artifacts::WalletKitZkArtifactSource,
    #[cfg(feature = "embed-zkeys")]
    walletkit_core::authenticator::artifacts::embedded::EmbeddedZkArtifacts,
    #[cfg(feature = "embed-zkeys")]
    walletkit_core::authenticator::artifacts::caching::CachingZkArtifacts,
    walletkit_core::flamingo::FlamingoMatcher,
    walletkit_core::flamingo::VerifiedMatchToken,
    #[cfg(feature = "issuers")]
    walletkit_core::issuers::TfhNfcIssuer,
    #[cfg(feature = "issuers")]
    walletkit_core::issuers::RecoveryBindingManager,
    #[cfg(feature = "v3")]
    walletkit_core::v3::common_apps::AddressBook,
    #[cfg(feature = "v3")]
    walletkit_core::v3::world_id::WorldId,
    #[cfg(feature = "v3")]
    walletkit_core::v3::proof::ProofContext,
    #[cfg(feature = "v3")]
    walletkit_core::v3::proof::ProofOutput,
    #[cfg(feature = "v3")]
    walletkit_core::v3::MerkleTreeProof,
}

/// The native interface version.
#[cfg_attr(feature = "jni", jni_export)]
pub const fn abi_version() -> u32 {
    ABI_VERSION
}

/// Creates a cancellation token for one async call.
#[cfg_attr(feature = "jni", jni_export)]
pub fn operation_new() -> Arc<OperationState> {
    Arc::new(OperationState::new())
}

/// Cancels an operation before or during its call. Unknown IDs are ignored.
#[cfg_attr(feature = "jni", jni_export)]
pub fn operation_cancel(operation: u64) {
    if let Ok(operation) = registry::get::<OperationState>(operation) {
        operation.cancel();
    }
}

/// Releases a handle of any type. Idempotent; running calls keep their own references.
#[cfg_attr(feature = "jni", jni_export)]
pub fn object_release(handle: u64) {
    registry::release(handle);
}
