use serde::{Serialize, Serializer};
use strum::{Display, EnumString};

use crate::Environment;

/// A `CredentialType` represents a specific credential which can be presented by a World ID holder.
///
/// For example, if a World ID is Orb-verified, the holder can use their `Orb` credential to prove they have a
/// valid Orb-verified credential.
///
/// More details in `https://docs.world.org/world-id/concepts#proof-of-personhood`
#[derive(Debug, Clone, Copy, PartialEq, Eq, EnumString, Hash, Display)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
#[strum(serialize_all = "lowercase")]
pub enum CredentialType {
    /// Represents persons who have been biometrically verified at an Orb. Highest level of proof of personhood verification.
    Orb,
    /// Verified biometric passport holder
    #[strum(serialize = "document")]
    Passport,
    /// Verified biometric passport holder with additional presence check verifications such as Chip Authentication
    /// The identity trapdoor is `secure_passport` but it's serialized as `secure_document` to match `idkit-js` and the Developer Portal.
    /// Reference: <https://github.com/worldcoin/idkit-js/blob/main/packages/core/src/types/config.ts#L18>
    #[strum(serialize = "secure_document")]
    SecurePassport,
    /// Represents a semi-unique device
    Device,
}

impl Serialize for CredentialType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl CredentialType {
    /// Returns a predefined seed string which is used to derive the identity commitment.
    ///
    /// [Protocol Reference](https://docs.semaphore.pse.dev/V2/technical-reference/circuits#proof-of-membership).
    ///
    /// For usage reference, review [sempahore-rs](https://github.com/worldcoin/semaphore-rs/blob/main/src/identity.rs#L44).
    ///
    ///  - For `Orb`, it's a fixed legacy default value. Changing this default would break existing verifying apps, hence its explicit specification here.
    /// - `Passport` (NFC-based check on government-issued passport)
    /// - `SecurePassport` (NFC-based check on government-issued passport with additional chip authentication checks)
    #[must_use]
    pub const fn as_identity_trapdoor(&self) -> &[u8] {
        match self {
            Self::Orb => b"identity_trapdoor",
            Self::Device => b"phone_credential",
            Self::Passport => b"passport",
            Self::SecurePassport => b"secure_passport",
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
                Self::Passport => "https://signup-document.stage-crypto.worldcoin.org",
                Self::SecurePassport => {
                    "https://signup-document-secure.stage-crypto.worldcoin.org"
                }
            },
            Environment::Production => match self {
                Self::Orb => "https://signup-orb-ethereum.crypto.worldcoin.org",
                Self::Device => "https://signup-phone-ethereum.crypto.worldcoin.org",
                Self::Passport => "https://signup-document.crypto.worldcoin.org",
                Self::SecurePassport => {
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

        let credential_type = CredentialType::SecurePassport;
        let serialized = serde_json::to_string(&credential_type).unwrap();
        assert_eq!(serialized, "\"secure_document\"");
    }
}
