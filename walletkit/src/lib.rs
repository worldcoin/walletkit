#![doc = include_str!("../README.md")]

extern crate walletkit_core;
#[cfg(feature = "ffi")]
walletkit_core::uniffi_reexport_scaffolding!();

pub use walletkit_core::*;

#[cfg(feature = "ffi")]
uniffi::setup_scaffolding!("walletkit");
