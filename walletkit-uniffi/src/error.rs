use std::fmt::{Display, Formatter};

#[derive(uniffi::Error, Debug)]
#[uniffi(flat_error)]
pub enum WalletKitError {
    E(walletkit::error::WalletKitError),
}

impl From<walletkit::error::WalletKitError> for WalletKitError {
    fn from(e: walletkit::error::WalletKitError) -> Self {
        Self::E(e)
    }
}

impl Display for WalletKitError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::E(e) => Display::fmt(e, f),
        }
    }
}

impl std::error::Error for WalletKitError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            WalletKitError::E(e) => Some(e),
        }
    }
}
