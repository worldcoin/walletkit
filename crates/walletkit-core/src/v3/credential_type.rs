use serde::{Deserialize, Serialize};
use strum::{Display, EnumString};

use crate::Environment;

/// A `CredentialType` represents a specific credential which can be presented by a World ID holder.
///
/// For example, if a World ID is Orb-verified, the holder can use their `Orb` credential to prove they have a
/// valid Orb-verified credential.
///
/// More details in `https://docs.world.org/world-id/concepts#proof-of-personhood`
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    EnumString,
    Hash,
    Display,
    Serialize,
    Deserialize,
    uniffi::Enum,
)]
#[strum(serialize_all = "snake_case")]
#[serde(rename_all = "snake_case")]
pub enum CredentialType {
    /// Represents persons who have been biometrically verified at an Orb. Highest level of proof of personhood verification.
    Orb,
    /// Verified biometric ICAO-9303 government-issued document holder
    #[strum(serialize = "document")]
    Document,
    /// Verified biometric ICAO-9303 government-issued document holder with additional presence checks
    /// such as Chip Authentication or Active Authentication.
    ///
    ///
    /// The identity trapdoor is `secure_passport` but it's serialized as `secure_document` to match `idkit-js` and the Developer Portal.
    /// Reference: <https://github.com/worldcoin/idkit-js/blob/main/packages/core/src/types/config.ts#L18>
    SecureDocument,
    /// Represents a semi-unique device
    Device,
}

impl CredentialType {
    /// Returns a predefined seed string which is used to derive the identity commitment.
    ///
    /// [Protocol Reference](https://docs.semaphore.pse.dev/V2/technical-reference/circuits#proof-of-membership).
    ///
    /// For usage reference, review [sempahore-rs](https://github.com/worldcoin/semaphore-rs/blob/main/src/identity.rs#L44).
    ///
    ///  - For `Orb`, it's a fixed legacy default value. Changing this default would break existing verifying apps, hence its explicit specification here.
    /// - `Document` (NFC-based check on government-issued document)
    /// - `SecureDocument` (NFC-based check on government-issued document with additional presence checks)
    #[must_use]
    pub const fn as_identity_trapdoor(&self) -> &[u8] {
        match self {
            Self::Orb => b"identity_trapdoor",
            Self::Device => b"phone_credential",
            Self::Document => b"passport",
            Self::SecureDocument => b"secure_passport",
        }
    }

    /// Returns the host name for the relevant sign up sequencer to use. The sign up sequencer is used to fetch Merkle inclusion proofs.
    ///
    /// [Reference](https://github.com/worldcoin/signup-sequencer)
    ///
    /// # Future
    /// - Support custom sign up sequencer hosts
    #[must_use]
    pub const fn get_sign_up_sequencer_host(&self, environment: &Environment) -> &str {
        match environment {
            Environment::Staging => match self {
                Self::Orb => "https://signup-orb-ethereum.stage-crypto.worldcoin.org",
                Self::Device => {
                    "https://signup-phone-ethereum.stage-crypto.worldcoin.org"
                }
                Self::Document => "https://signup-document.stage-crypto.worldcoin.org",
                Self::SecureDocument => {
                    "https://signup-document-secure.stage-crypto.worldcoin.org"
                }
            },
            Environment::Production => match self {
                Self::Orb => "https://signup-orb-ethereum.crypto.worldcoin.org",
                Self::Device => "https://signup-phone-ethereum.crypto.worldcoin.org",
                Self::Document => "https://signup-document.crypto.worldcoin.org",
                Self::SecureDocument => {
                    "https://signup-document-secure.crypto.worldcoin.org"
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credential_type_serialization() {
        let credential_type = CredentialType::Device;
        let serialized = serde_json::to_string(&credential_type).unwrap();
        assert_eq!(serialized, "\"device\"");

        let credential_type = CredentialType::SecureDocument;
        let serialized = serde_json::to_string(&credential_type).unwrap();
        assert_eq!(serialized, "\"secure_document\"");
    }

    #[test]
    fn test_credential_type_deserialization() {
        let deserialized: CredentialType =
            serde_json::from_str("\"document\"").unwrap();
        assert_eq!(deserialized, CredentialType::Document);

        let deserialized: CredentialType =
            serde_json::from_str("\"secure_document\"").unwrap();
        assert_eq!(deserialized, CredentialType::SecureDocument);

        // Test invalid credential type
        let result: Result<CredentialType, _> = serde_json::from_str("\"invalid\"");
        assert!(result.is_err());
    }

    #[test]
    fn test_credential_type_roundtrip() {
        // Test that serialize -> deserialize gives back the original value
        let variants = vec![
            CredentialType::Orb,
            CredentialType::Device,
            CredentialType::Document,
            CredentialType::SecureDocument,
        ];

        for variant in variants {
            let serialized = serde_json::to_string(&variant).unwrap();
            let deserialized: CredentialType =
                serde_json::from_str(&serialized).unwrap();
            assert_eq!(variant, deserialized, "Roundtrip failed for {variant:?}");
        }
    }
}
