//! `FieldElement` represents an element in a finite field used in the World ID Protocol's
//! zero-knowledge proofs.
use std::ops::Deref;
use std::str::FromStr;

use world_id_core::FieldElement as CoreFieldElement;

use crate::error::WalletKitError;

/// A wrapper around `FieldElement` to enable FFI interoperability.
///
/// `FieldElement` represents an element in a finite field used in the World ID Protocol's
/// zero-knowledge proofs. This wrapper allows the type to be safely passed across FFI boundaries
/// while maintaining proper serialization and deserialization semantics.
///
/// Field elements are typically 32 bytes when serialized.
#[allow(clippy::module_name_repetitions)]
#[derive(Debug, Clone, uniffi::Object)]
pub struct FieldElement(pub CoreFieldElement);

#[uniffi::export]
impl FieldElement {
    /// Creates a `FieldElement` from raw bytes (big-endian).
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes cannot be deserialized into a valid field element.
    #[uniffi::constructor]
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, WalletKitError> {
        let len = bytes.len();
        let val: [u8; 32] =
            bytes.try_into().map_err(|_| WalletKitError::InvalidInput {
                attribute: "field_element".to_string(),
                reason: format!("Expected 32 bytes for field element, got {len}"),
            })?;

        let field_element = CoreFieldElement::from_be_bytes(&val)?;
        Ok(Self(field_element))
    }

    /// Creates a `FieldElement` from a `u64` value.
    ///
    /// This is useful for testing or when working with small field element values.
    #[must_use]
    #[uniffi::constructor]
    pub fn from_u64(value: u64) -> Self {
        Self(CoreFieldElement::from(value))
    }

    /// Serializes the field element to bytes (big-endian).
    ///
    /// Returns a byte vector representing the field element.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_be_bytes().to_vec()
    }

    /// Creates a `FieldElement` from a hex string.
    ///
    /// The hex string can optionally start with "0x".
    ///
    /// # Errors
    ///
    /// Returns an error if the hex string is invalid or cannot be parsed.
    #[uniffi::constructor]
    pub fn try_from_hex_string(hex_string: &str) -> Result<Self, WalletKitError> {
        let fe = CoreFieldElement::from_str(hex_string)?;
        Ok(Self(fe))
    }

    /// Converts the field element to a hex-encoded, padded string.
    #[must_use]
    pub fn to_hex_string(&self) -> String {
        self.0.to_string()
    }
}

impl From<FieldElement> for CoreFieldElement {
    fn from(val: FieldElement) -> Self {
        val.0
    }
}

impl From<CoreFieldElement> for FieldElement {
    fn from(val: CoreFieldElement) -> Self {
        Self(val)
    }
}

impl From<u64> for FieldElement {
    fn from(value: u64) -> Self {
        Self(CoreFieldElement::from(value))
    }
}

impl Deref for FieldElement {
    type Target = CoreFieldElement;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_u64() {
        let fe = FieldElement::from_u64(42);
        let bytes = fe.to_bytes();
        assert!(!bytes.is_empty());
        assert_eq!(bytes[31], 0x2a);
    }

    #[test]
    fn test_round_trip_bytes() {
        let original = FieldElement::from_u64(12345);
        let bytes = original.to_bytes();
        let restored = FieldElement::from_bytes(bytes).unwrap();

        // Compare the serialized forms since FieldElement doesn't implement PartialEq
        let original_bytes = original.to_bytes();
        let restored_bytes = restored.to_bytes();
        assert_eq!(original_bytes, restored_bytes);
    }

    #[test]
    fn test_hex_round_trip() {
        let original = FieldElement::from_u64(999);
        let hex = original.to_hex_string();
        let restored = FieldElement::try_from_hex_string(&hex).unwrap();

        let original_bytes = original.to_bytes();
        let restored_bytes = restored.to_bytes();
        assert_eq!(original_bytes, restored_bytes);
    }

    #[test]
    fn test_hex_string_with_and_without_0x() {
        let fe = FieldElement::from_u64(255);
        let hex = fe.to_hex_string();

        // Should work with 0x prefix
        let with_prefix = FieldElement::try_from_hex_string(&hex).unwrap();

        // Should also work without 0x prefix
        let hex_no_prefix = hex.trim_start_matches("0x");
        let without_prefix = FieldElement::try_from_hex_string(hex_no_prefix).unwrap();

        let with_bytes = with_prefix.to_bytes();
        let without_bytes = without_prefix.to_bytes();
        assert_eq!(with_bytes, without_bytes);
    }

    #[test]
    fn test_invalid_hex_string() {
        assert!(FieldElement::try_from_hex_string("0xZZZZ").is_err());
        assert!(FieldElement::try_from_hex_string("not hex").is_err());
    }

    /// Ensures encoding is consistent with different round trips
    #[test]
    fn test_encoding_round_trip() {
        let sub_one = CoreFieldElement::from(42u64);
        let sub_two = FieldElement::from(sub_one);

        assert_eq!(sub_one, *sub_two);
        assert_eq!(sub_one.to_string(), sub_two.to_hex_string());

        let sub_three = FieldElement::try_from_hex_string(&sub_two.to_hex_string()).unwrap();
        assert_eq!(sub_one, *sub_three);
    }
}
