use alloy_primitives::Address;
use std::str::FromStr;

use crate::error::WalletKitError;

/// A trait for parsing primitive types from foreign bindings.
///
/// This trait is used to parse primitive types from foreign provided values. For example, parsing
/// a stringified address into an `Address` type.
///
/// # Examples
/// ```rust,ignore
/// let address = Address::parse_from_ffi("0x1234567890abcdef", "address");
/// ```
///
/// # Errors
/// - `PrimitiveError::InvalidInput` if the provided string is not a valid address.
pub trait ParseFromForeignBinding {
    fn parse_from_ffi(s: &str, attr: &'static str) -> Result<Self, WalletKitError>
    where
        Self: Sized;
    fn parse_from_ffi_optional(
        s: Option<String>,
        attr: &'static str,
    ) -> Result<Option<Self>, WalletKitError>
    where
        Self: Sized;
}

impl ParseFromForeignBinding for Address {
    fn parse_from_ffi(s: &str, attr: &'static str) -> Result<Self, WalletKitError> {
        Self::from_str(s).map_err(|e| WalletKitError::InvalidInput {
            attribute: attr.to_string(),
            reason: e.to_string(),
        })
    }
    fn parse_from_ffi_optional(
        s: Option<String>,
        attr: &'static str,
    ) -> Result<Option<Self>, WalletKitError> {
        if let Some(s) = s {
            return Self::parse_from_ffi(s.as_str(), attr).map(Some);
        }
        Ok(None)
    }
}
