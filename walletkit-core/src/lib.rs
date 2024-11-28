#![deny(clippy::all, clippy::pedantic, clippy::nursery)]

pub mod credential_type;
pub mod error;
pub mod identity;
pub mod proof;
pub mod u256;

uniffi::setup_scaffolding!("walletkit_core");
