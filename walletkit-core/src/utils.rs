use ruint::aliases::U256;

use crate::error::Error;

/// A trait for types that can be represented as a hex string.
///
/// This trait is implemented for `U256` and can be used to convert between hex strings and numbers.
/// Most inputs and outputs from the zero-knowledge proofs are `U256` values.
/// While using `U256` directly is convenient and recommended when working with the proofs, particularly in Rust,
/// it is not a user-friendly type for interactions or communications in other languages / systems.
///
/// Particularly, when sending proof inputs/outputs as JSON on HTTP requests, the values SHOULD be represented as hex strings.
pub trait HexNumber {
    /// Convert the value to a hex string.
    fn to_hex_string(&self) -> String;
    /// Convert a hex string to a `U256`.
    ///
    /// # Errors
    ///
    /// Returns an error if the hex string is invalid as a `U256`.
    fn try_from_hex_string(hex: &str) -> Result<Self, Error>
    where
        Self: std::marker::Sized;
}

impl HexNumber for U256 {
    fn to_hex_string(&self) -> String {
        format!("{self:#066x}")
    }

    fn try_from_hex_string(hex: &str) -> Result<Self, Error> {
        Self::from_str_radix(hex, 16).map_err(Error::U256ParsingError)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ruint::uint;

    #[test]
    fn test_to_hex_string_for_u256() {
        assert_eq!(
            U256::from(1).to_hex_string(),
            "0x0000000000000000000000000000000000000000000000000000000000000001"
        );
        assert_eq!(
            U256::from(42).to_hex_string(),
            "0x000000000000000000000000000000000000000000000000000000000000002a"
        );

        assert_eq!(
            uint!(999999_U256).to_hex_string(),
            "0x00000000000000000000000000000000000000000000000000000000000f423f"
        );

        assert_eq!(
            uint!(80084422859880547211683076133703299733277748156566366325829078699459944778998_U256).to_hex_string(),
            "0xb10e2d527612073b26eecdfd717e6a320cf44b4afac2b0732d9fcbe2b7fa0cf6"
        );

        assert_eq!(
            uint!(0x036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0_U256).to_hex_string(),
            "0x036b6384b5eca791c62761152d0c79bb0604c104a5fb6f4eb0703f3154bb3db0"
        );
    }

    #[test]
    fn test_try_from_hex_string() {
        // Test valid hex strings
        assert_eq!(U256::try_from_hex_string("0x2a").unwrap(), U256::from(42));
        assert_eq!(U256::try_from_hex_string("2a").unwrap(), U256::from(42));

        // Test larger numbers
        assert_eq!(U256::try_from_hex_string("0xf423f").unwrap(), U256::from(999999));

        // Test zero
        assert_eq!(U256::try_from_hex_string("0x0").unwrap(), U256::from(0));

        // Test invalid hex strings
        assert!(U256::try_from_hex_string("0xg").is_err());
        assert!(U256::try_from_hex_string("not hex").is_err());
    }
}
