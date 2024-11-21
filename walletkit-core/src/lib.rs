#![deny(clippy::all, clippy::pedantic, clippy::nursery)]

pub mod error;
pub mod field;
pub mod identity;
pub mod proof;
mod utils;
pub use utils::*;

uniffi::setup_scaffolding!("walletkit_core");
