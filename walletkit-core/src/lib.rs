#![deny(clippy::all, clippy::pedantic, clippy::nursery)]

use strum::EnumString;

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Object, EnumString)]
#[strum(serialize_all = "lowercase")]
pub enum Environment {
    Staging,
    Production,
}

pub mod credential_type;
pub mod error;
pub mod identity;
mod merkle_tree;
pub mod proof;
mod request;
pub mod u256;

uniffi::setup_scaffolding!("walletkit_core");
