#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    missing_docs,
    dead_code
)]
#![doc = include_str!("../README.md")]

extern crate walletkit_core;
walletkit_core::uniffi_reexport_scaffolding!();

pub use walletkit_core::*;

uniffi::setup_scaffolding!("walletkit");
