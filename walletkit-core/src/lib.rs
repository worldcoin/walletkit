#![deny(clippy::all, clippy::pedantic, clippy::nursery)]
use strum::EnumString;

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Object, EnumString)]
#[strum(serialize_all = "lowercase")]
pub enum Environment {
    Staging,
    Production,
}

mod credential_type;
pub use credential_type::*;

mod error;
pub use error::*;

mod identity;
pub use identity::*;

mod proof;
pub use proof::*;

mod u256;
pub use u256::*;

// private modules
mod merkle_tree;
mod request;

uniffi::setup_scaffolding!("walletkit_core");
