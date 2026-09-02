//! Interfaces for consumer-supplied platform integrations.
//!
//! Argument shapes (`Vec<u8>`, owned `String`) mostly mirror `WalletKit`'s
//! existing uniffi-annotated traits so consumers can bridge with a thin
//! newtype that just delegates and maps errors. (A blanket impl across
//! crates is blocked by Rust's orphan rule, so consumers do need a small
//! wrapper.) `KeySealer::seal` is the one exception: it borrows its
//! plaintext so the secret is never owned by this crate longer than
//! necessary; a bridge to an owned-only interface (e.g. a uniffi callback)
//! still needs one copy at that boundary.

use crate::error::StoreResult;

/// Host interface for sealing and unsealing secrets.
///
/// Implementations must bind sealed values to `context`, whether through AEAD
/// additional authenticated data, context-specific key selection, or an
/// equivalent mechanism. Unsealing with a different context must fail.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait KeySealer: Send + Sync {
    /// Seals plaintext and binds it to `context`.
    ///
    /// `plaintext` is borrowed rather than owned so that callers holding it
    /// in a zeroizing buffer (e.g. `Zeroizing<[u8; 32]>`) never have to
    /// hand ownership of an un-zeroized copy to this trait.
    ///
    /// # Errors
    ///
    /// Returns an error if the key sealer refuses the operation or sealing
    /// fails.
    async fn seal(&self, context: &[u8], plaintext: &[u8]) -> StoreResult<Vec<u8>>;

    /// Unseals ciphertext after verifying its binding to `context`. The
    /// same context supplied at seal time must be supplied here or the
    /// operation must fail.
    ///
    /// # Errors
    ///
    /// Returns an error if authentication fails or the key cannot be unsealed.
    async fn unseal(
        &self,
        context: Vec<u8>,
        ciphertext: Vec<u8>,
    ) -> StoreResult<Vec<u8>>;
}

/// Atomic blob store for small binary files (e.g. sealed key envelopes).
///
/// Provided by the host rather than calling `std::fs` directly for two
/// reasons:
///
/// - **WASM has no `std::fs`.** On `wasm32-unknown-unknown` the runtime
///   is a Web Worker; the host backs storage with `OPFS`, `IndexedDB`,
///   or similar.
/// - **Hosts own where data lives.** iOS sandboxed app-data containers,
///   Android per-UID data dirs, iCloud-skip flags, atomic-write
///   semantics — all platform-specific. walletkit-db stays neutral.
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
pub trait AtomicBlobStore: Send + Sync {
    /// Reads the blob at `path`, if present.
    ///
    /// # Errors
    ///
    /// Returns an error if the read fails.
    async fn read(&self, path: String) -> StoreResult<Option<Vec<u8>>>;

    /// Writes bytes atomically to `path`.
    ///
    /// # Errors
    ///
    /// Returns an error if the write fails.
    async fn write_atomic(&self, path: String, bytes: Vec<u8>) -> StoreResult<()>;

    /// Deletes the blob at `path`.
    ///
    /// # Errors
    ///
    /// Returns an error if the delete fails.
    async fn delete(&self, path: String) -> StoreResult<()>;
}
