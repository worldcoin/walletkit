mod hello;
pub use self::hello::*;

mod error;
pub use error::*;

pub type WalletKitResult<T, E = WalletKitError> = std::result::Result<T, E>;

uniffi::setup_scaffolding!("wallet-kit");
