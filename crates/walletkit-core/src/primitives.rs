use alloy_core::primitives::Address;
use ruint::aliases::U256;
use std::str::FromStr;
use world_id_core::EdDSAPublicKey;

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
        Self: Sized,
    {
        if let Some(s) = s {
            return Self::parse_from_ffi(s.as_str(), attr).map(Some);
        }
        Ok(None)
    }
}

impl ParseFromForeignBinding for Address {
    fn parse_from_ffi(s: &str, attr: &'static str) -> Result<Self, WalletKitError> {
        Self::from_str(s).map_err(|e| WalletKitError::InvalidInput {
            attribute: attr.to_string(),
            reason: e.to_string(),
        })
    }
}

impl ParseFromForeignBinding for EdDSAPublicKey {
    /// Parses a compressed `BabyJubJub` public key from a `0x`-prefixed,
    /// zero-padded 32-byte hex string.
    fn parse_from_ffi(s: &str, attr: &'static str) -> Result<Self, WalletKitError> {
        let invalid_input = |reason: String| WalletKitError::InvalidInput {
            attribute: attr.to_string(),
            reason,
        };
        let hex = s.strip_prefix("0x").ok_or_else(|| {
            invalid_input(
                "Public key must be a 0x-prefixed 32-byte hex string".to_string(),
            )
        })?;

        if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(invalid_input(
                "Public key must be a 0x-prefixed 32-byte hex string".to_string(),
            ));
        }

        let encoded = U256::from_str_radix(hex, 16)
            .map_err(|error| invalid_input(error.to_string()))?;
        Self::from_compressed_bytes(encoded.to_le_bytes())
            .map_err(|error| invalid_input(error.to_string()))
    }
}
