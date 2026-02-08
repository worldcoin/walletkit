//! `FieldElement` represents an element in a finite field used in the World ID Protocol's
//! zero-knowledge proofs.
use std::io::Cursor;
use std::ops::Deref;

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
    /// Creates a `FieldElement` from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes cannot be deserialized into a valid field element.
    #[uniffi::constructor]
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, WalletKitError> {
        let field_element = CoreFieldElement::deserialize_from_bytes(&mut Cursor::new(
            bytes,
        ))
        .map_err(|e| WalletKitError::InvalidInput {
            attribute: "field_element_bytes".to_string(),
            reason: format!("Failed to deserialize field element: {e}"),
        })?;
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

    /// Serializes the field element to bytes.
    ///
    /// Returns a byte vector representing the field element.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn to_bytes(&self) -> Result<Vec<u8>, WalletKitError> {
        let mut bytes = Vec::new();
        self.0.serialize_as_bytes(&mut bytes).map_err(|e| {
            WalletKitError::SerializationError {
                error: format!("Failed to serialize field element: {e}"),
            }
        })?;
        Ok(bytes)
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
        let hex_string = hex_string.trim().trim_start_matches("0x");
        let bytes =
            hex::decode(hex_string).map_err(|e| WalletKitError::InvalidInput {
                attribute: "field_element_hex".to_string(),
                reason: format!("Invalid hex string: {e}"),
            })?;
        Self::from_bytes(bytes)
    }

    /// Converts the field element to a hex string.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn to_hex_string(&self) -> Result<String, WalletKitError> {
        let bytes = self.to_bytes()?;
        Ok(format!("0x{}", hex::encode(bytes)))
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
        let bytes = fe.to_bytes().unwrap();
        assert!(!bytes.is_empty());
    }

    #[test]
    fn test_round_trip_bytes() {
        let original = FieldElement::from_u64(12345);
        let bytes = original.to_bytes().unwrap();
        let restored = FieldElement::from_bytes(bytes).unwrap();

        // Compare the serialized forms since FieldElement doesn't implement PartialEq
        let original_bytes = original.to_bytes().unwrap();
        let restored_bytes = restored.to_bytes().unwrap();
        assert_eq!(original_bytes, restored_bytes);
    }

    #[test]
    fn test_hex_round_trip() {
        let original = FieldElement::from_u64(999);
        let hex = original.to_hex_string().unwrap();
        let restored = FieldElement::try_from_hex_string(&hex).unwrap();

        let original_bytes = original.to_bytes().unwrap();
        let restored_bytes = restored.to_bytes().unwrap();
        assert_eq!(original_bytes, restored_bytes);
    }

    #[test]
    fn test_hex_string_with_and_without_0x() {
        let fe = FieldElement::from_u64(255);
        let hex = fe.to_hex_string().unwrap();

        // Should work with 0x prefix
        let with_prefix = FieldElement::try_from_hex_string(&hex).unwrap();

        // Should also work without 0x prefix
        let hex_no_prefix = hex.trim_start_matches("0x");
        let without_prefix = FieldElement::try_from_hex_string(hex_no_prefix).unwrap();

        let with_bytes = with_prefix.to_bytes().unwrap();
        let without_bytes = without_prefix.to_bytes().unwrap();
        assert_eq!(with_bytes, without_bytes);
    }

    #[test]
    fn test_invalid_hex_string() {
        assert!(FieldElement::try_from_hex_string("0xZZZZ").is_err());
        assert!(FieldElement::try_from_hex_string("not hex").is_err());
    }
}
