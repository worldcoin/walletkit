//! PROTOTYPE: browser bindings for WalletKit's existing UniFFI API.

extern crate walletkit_core;

#[cfg(target_arch = "wasm32")]
extern crate uniffi_runtime_wasm as _;

walletkit_core::uniffi_reexport_scaffolding!();

pub use walletkit_core::*;

uniffi::setup_scaffolding!("walletkit_web_authenticator_poc");
