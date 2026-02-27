#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    missing_docs,
    dead_code
)]
#![doc = include_str!("../README.md")]

extern crate walletkit_core;
#[cfg(not(target_arch = "wasm32"))]
walletkit_core::uniffi_reexport_scaffolding!();

pub use walletkit_core::*;

#[cfg(not(target_arch = "wasm32"))]
uniffi::setup_scaffolding!("walletkit");
