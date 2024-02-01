pub mod hello;
pub use self::hello::*;

pub mod error;
pub use error::*;

pub type WalletKitResult<T, E = WalletKitError> = std::result::Result<T, E>;
