//! `WalletKit` Rust interface plus the typed JNI (`jni`) and C (`c`) bindings used by the
//! maintained Kotlin and Swift SDKs.

pub use walletkit_core::*;

#[cfg(all(feature = "native", not(target_arch = "wasm32")))]
mod native;
