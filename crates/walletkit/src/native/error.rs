//! Errors crossing the boundary: structured data, never formatted input payloads.
//!
//! An encoded error is `domain:u8` followed by the domain value in the binary encoding:
//!
//! | domain | value |
//! |---|---|
//! | 0 | bridge failure: `code:str` |
//! | 1 | `WalletKitError` |
//! | 2 | `StorageError` |
//! | 3 | `FlamingoError` |
//! | 4 | `CredentialConstraintsCheckError` |
//!
//! Bridge codes are fixed identifiers such as `InvalidInput`, `InvalidHandle`, or
//! `Cancelled`; hosts map `Cancelled` to their cancellation error.

use super::codec::{Encode, Writer};
use walletkit_core::{
    error::WalletKitError, flamingo::FlamingoError,
    proof_request_credential_constraints_check::CredentialConstraintsCheckError,
    storage::StorageError,
};

pub type Result<T> = std::result::Result<T, NativeError>;

/// A failure reported to the host.
pub enum NativeError {
    /// A transport, ownership, or cancellation failure identified by a fixed code.
    Bridge(&'static str),
    /// A `WalletKitError`.
    WalletKit(WalletKitError),
    /// A `StorageError`.
    Storage(StorageError),
    /// A `FlamingoError`.
    Flamingo(FlamingoError),
    /// A `CredentialConstraintsCheckError`.
    CredentialConstraintsCheck(CredentialConstraintsCheckError),
}

impl NativeError {
    /// A bridge failure.
    pub const fn bridge(code: &'static str) -> Self {
        Self::Bridge(code)
    }

    /// Malformed host input, such as invalid UTF-8 or an unknown enumeration ordinal.
    pub const fn invalid_input() -> Self {
        Self::Bridge("InvalidInput")
    }

    /// Cancellation before or during an operation.
    pub const fn cancelled() -> Self {
        Self::Bridge("Cancelled")
    }

    /// Encodes the error. Falls back to a bridge code if a domain value cannot be encoded.
    pub fn encode(self) -> Vec<u8> {
        let mut writer = Writer::default();
        let encoded = match self {
            Self::Bridge(code) => {
                writer.u8(0);
                writer.string(code)
            }
            Self::WalletKit(error) => {
                writer.u8(1);
                error.encode(&mut writer)
            }
            Self::Storage(error) => {
                writer.u8(2);
                error.encode(&mut writer)
            }
            Self::Flamingo(error) => {
                writer.u8(3);
                error.encode(&mut writer)
            }
            Self::CredentialConstraintsCheck(error) => {
                writer.u8(4);
                error.encode(&mut writer)
            }
        };
        match encoded {
            Ok(()) => writer.into_bytes(),
            Err(_) => Self::bridge("ErrorEncodingFailed").encode(),
        }
    }
}

impl std::fmt::Debug for NativeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bridge(code) => write!(formatter, "WalletKitBridge::{code}"),
            Self::WalletKit(_) => formatter.write_str("WalletKitError"),
            Self::Storage(_) => formatter.write_str("StorageError"),
            Self::Flamingo(_) => formatter.write_str("FlamingoError"),
            Self::CredentialConstraintsCheck(_) => {
                formatter.write_str("CredentialConstraintsCheckError")
            }
        }
    }
}

impl From<WalletKitError> for NativeError {
    fn from(error: WalletKitError) -> Self {
        Self::WalletKit(error)
    }
}

impl From<StorageError> for NativeError {
    fn from(error: StorageError) -> Self {
        Self::Storage(error)
    }
}

impl From<FlamingoError> for NativeError {
    fn from(error: FlamingoError) -> Self {
        Self::Flamingo(error)
    }
}

impl From<CredentialConstraintsCheckError> for NativeError {
    fn from(error: CredentialConstraintsCheckError) -> Self {
        Self::CredentialConstraintsCheck(error)
    }
}
