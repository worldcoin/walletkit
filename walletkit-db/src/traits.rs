//! Interfaces for consumer-supplied platform integrations.
//!
//! Argument shapes (`Vec<u8>`, owned `String`) mirror `WalletKit`'s existing
//! uniffi-annotated traits so consumers can bridge with a thin newtype that
//! just delegates and maps errors. (A blanket impl across crates is blocked
//! by Rust's orphan rule, so consumers do need a small wrapper.)

use crate::error::StoreResult;

/// Device keystore for sealing and opening secrets under a device-bound key.
///
/// Implementations MUST use an AEAD construction (e.g. AES-GCM or
/// ChaCha20-Poly1305) so that `aad` (additional authenticated data) is
/// authenticated as part of the seal: any mismatch when opening must fail.
pub trait Keystore: Send + Sync {
    /// Seals plaintext under the device-bound key, authenticating `aad`
    /// (additional authenticated data).
    ///
    /// # Errors
    ///
    /// Returns an error if the keystore refuses the operation or the seal
    /// fails.
    fn seal(&self, aad: Vec<u8>, plaintext: Vec<u8>) -> StoreResult<Vec<u8>>;

    /// Opens ciphertext under the device-bound key, verifying `aad`. The
    /// same `aad` supplied at seal time must be supplied here or the open
    /// operation must fail.
    ///
    /// # Errors
    ///
    /// Returns an error if authentication fails or the keystore cannot open.
    fn open_sealed(&self, aad: Vec<u8>, ciphertext: Vec<u8>) -> StoreResult<Vec<u8>>;
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
pub trait AtomicBlobStore: Send + Sync {
    /// Reads the blob at `path`, if present.
    ///
    /// # Errors
    ///
    /// Returns an error if the read fails.
    fn read(&self, path: String) -> StoreResult<Option<Vec<u8>>>;

    /// Writes bytes atomically to `path`.
    ///
    /// # Errors
    ///
    /// Returns an error if the write fails.
    fn write_atomic(&self, path: String, bytes: Vec<u8>) -> StoreResult<()>;

    /// Deletes the blob at `path`.
    ///
    /// # Errors
    ///
    /// Returns an error if the delete fails.
    fn delete(&self, path: String) -> StoreResult<()>;
}
