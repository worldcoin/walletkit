use std::ops::Deref;

use crate::error::WalletKitError;
use ruint::aliases::U256;
use serde::{Deserialize, Serialize};

/// A wrapper around `U256` to represent a field element in the protocol. Wrapper enables FFI interoperability.
///
/// Most inputs and outputs from the zero-knowledge proofs are `U256` values.
/// While using `U256` directly is convenient and recommended when working with the proofs, particularly in Rust,
/// it is not a user-friendly type for interactions or communications in other languages / systems.
///
/// Particularly, when sending proof inputs/outputs as JSON on HTTP requests, the values SHOULD
/// be represented as padded hex strings from Big Endian bytes.
#[allow(clippy::module_name_repetitions)]
#[derive(uniffi::Object, Debug, PartialEq, Eq, Clone, Copy)]
pub struct U256Wrapper(pub U256);

#[uniffi::export]
impl U256Wrapper {
    /// Outputs a hex string representation of the `U256` value padded to 32 bytes (plus two bytes for the `0x` prefix).
    #[must_use]
    pub fn to_hex_string(&self) -> String {
        format!("{:#066x}", self.0)
    }

    /// Attempts to parse a hex string as a `U256` value (wrapped).
    ///
    /// # Errors
    /// Will return an `Error::InvalidNumber` if the input is not a valid hex-string-presented number up to 256 bits.
    #[uniffi::constructor]
    pub fn try_from_hex_string(hex_string: &str) -> Result<Self, WalletKitError> {
        let hex_string = hex_string.trim().trim_start_matches("0x");

        let number = U256::from_str_radix(hex_string, 16)
            .map_err(|_| WalletKitError::InvalidNumber)?;

        Ok(Self(number))
    }
}

impl From<U256Wrapper> for U256 {
    fn from(val: U256Wrapper) -> Self {
        val.0
    }
}

impl From<U256> for U256Wrapper {
    fn from(val: U256) -> Self {
        Self(val)
    }
}

impl std::fmt::Display for U256Wrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex_string())
    }
}

impl Deref for U256Wrapper {
    type Target = U256;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Serialize for U256Wrapper {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_hex_string())
    }
}

impl<'de> Deserialize<'de> for U256Wrapper {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::try_from_hex_string(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ruint::uint;

    #[test]
    fn test_to_hex_string_for_u256() {
        assert_eq!(
            U256Wrapper(U256::from(1)).to_hex_string(),
            "0x0000000000000000000000000000000000000000000000000000000000000001"
        );
        assert_eq!(
            U256Wrapper(U256::from(42)).to_hex_string(),
            "0x000000000000000000000000000000000000000000000000000000000000002a"
        );

        assert_eq!(
            U256Wrapper(uint!(999999_U256)).to_hex_string(),
            "0x00000000000000000000000000000000000000000000000000000000000f423f"
        );

        assert_eq!(
            U256Wrapper(uint!(
                80084422859880547211683076133703299733277748156566366325829078699459944778998_U256
            ))
            .to_hex_string(),
            "0xb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6"
        );

        assert_eq!(
            U256Wrapper(uint!(
                0x036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0_U256
            ))
            .to_hex_string(),
            "0x036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0"
        );
    }

    #[test]
    fn test_from_hex_string_for_u256() {
        assert_eq!(
            U256Wrapper::try_from_hex_string(
                "0x0000000000000000000000000000000000000000000000000000000000000001"
            )
            .unwrap(),
            U256Wrapper(U256::from(1))
        );
        assert_eq!(
            U256Wrapper::try_from_hex_string(
                "0x000000000000000000000000000000000000000000000000000000000000002a"
            )
            .unwrap(),
            U256Wrapper(U256::from(42))
        );

        assert_eq!(
            U256Wrapper::try_from_hex_string(
                "0x00000000000000000000000000000000000000000000000000000000000f423f"
            )
            .unwrap(),
            U256Wrapper(uint!(999999_U256))
        );

        assert_eq!(
            U256Wrapper::try_from_hex_string("0xb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6").unwrap(),
            U256Wrapper(uint!(
                80084422859880547211683076133703299733277748156566366325829078699459944778998_U256
            ))
        );

        assert_eq!(
            U256Wrapper::try_from_hex_string(
                "0x036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0"
            )
            .unwrap()
            .0,
            uint!(
                0x036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0_U256
            )
        );
    }

    #[test]
    fn test_invalid_hex_string() {
        assert!(U256Wrapper::try_from_hex_string("0xZZZZ").is_err());
        assert!(U256Wrapper::try_from_hex_string("1g").is_err());
        assert!(U256Wrapper::try_from_hex_string("not a hex string").is_err());
    }

    #[test]
    fn test_json_serializing() {
        let number = U256Wrapper(uint!(
            0x036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0_U256
        ));

        let json = serde_json::to_string(&number).unwrap();
        assert_eq!(
            json,
            "\"0x036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0\""
        );
    }
}
