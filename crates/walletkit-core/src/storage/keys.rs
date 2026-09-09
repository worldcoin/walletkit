//! Resolved database keys, independent of their source.

use secrecy::SecretBox;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::error::{StorageError, StorageResult};

/// Resolved in-memory database keys, independent of their source.
///
/// Keys are zeroized when the last owner drops this object.
#[derive(Zeroize, ZeroizeOnDrop, uniffi::Object)]
#[allow(clippy::struct_field_names)]
pub struct StorageKeys {
    intermediate_key: SecretBox<[u8; 32]>,
}

#[uniffi::export]
impl StorageKeys {
    /// Takes a resolved 32-byte database key, for example derived from a passkey PRF.
    ///
    /// # Errors
    /// Returns an error if the key is not exactly 32 bytes.
    #[uniffi::constructor]
    pub fn from_bytes(database_key: Vec<u8>) -> StorageResult<Self> {
        let database_key = Zeroizing::new(database_key);
        if database_key.len() != 32 {
            return Err(StorageError::InvalidInput(
                "expected a 32-byte database key".into(),
            ));
        }
        let intermediate_key = SecretBox::init_with(|| {
            let mut key = [0; 32];
            key.copy_from_slice(&database_key);
            key
        });
        Ok(Self { intermediate_key })
    }
}

impl StorageKeys {
    pub(crate) const fn from_secret(intermediate_key: SecretBox<[u8; 32]>) -> Self {
        Self { intermediate_key }
    }

    /// Returns a reference to the intermediate key's [`SecretBox`].
    #[must_use]
    pub const fn intermediate_key(&self) -> &SecretBox<[u8; 32]> {
        &self.intermediate_key
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn direct_key_requires_exactly_32_bytes() {
        for length in [0, 31, 33] {
            assert!(matches!(
                StorageKeys::from_bytes(vec![7; length]),
                Err(StorageError::InvalidInput(_))
            ));
        }
        let keys = StorageKeys::from_bytes(vec![7; 32]).expect("direct key");
        assert_eq!(keys.intermediate_key().expose_secret(), &[7; 32]);
    }
}
