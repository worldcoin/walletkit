//! `WalletKit` is the reference implementation for World ID clients.
//!
//! It provides the Rust API and `UniFFI` bindings used by mobile applications
//! to interact with World ID. The public API is re-exported from
//! [`walletkit_core`].

extern crate walletkit_core;
walletkit_core::uniffi_reexport_scaffolding!();

pub use walletkit_core::*;

uniffi::setup_scaffolding!("walletkit");
