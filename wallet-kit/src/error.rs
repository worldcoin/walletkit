use thiserror::Error;

#[derive(Debug, Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum WalletKitError {
    #[error("hello error")]
    Hello,
}
