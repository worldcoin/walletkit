use alloy_core::primitives::Address;
use std::str::FromStr;

use crate::error::WalletKitError;

/// A 256-bit unsigned integer with the existing hexadecimal serde representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct Uint256(pub ruint::aliases::U256);

impl Uint256 {
    /// Formats exactly 32 big-endian bytes, prefixed with `0x`.
    #[must_use]
    pub fn to_padded_hex_string(&self) -> String {
        format!("{:#066x}", self.0)
    }
}

impl std::ops::Deref for Uint256 {
    type Target = ruint::aliases::U256;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<ruint::aliases::U256> for Uint256 {
    fn from(value: ruint::aliases::U256) -> Self {
        Self(value)
    }
}

impl From<Uint256> for ruint::aliases::U256 {
    fn from(value: Uint256) -> Self {
        value.0
    }
}

impl std::fmt::Display for Uint256 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for Uint256 {
    type Err = ruint::ParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        value.parse().map(Self)
    }
}

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
#[allow(dead_code)]
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
