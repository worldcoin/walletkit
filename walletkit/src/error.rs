use thiserror::Error;

#[derive(Debug, Error)]
pub enum WalletKitError {
    #[error("hello error")]
    Hello,
}
