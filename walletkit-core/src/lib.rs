#![deny(clippy::all, clippy::pedantic, clippy::nursery, clippy::cargo)]

pub mod math;

uniffi::setup_scaffolding!("walletkit_core");
