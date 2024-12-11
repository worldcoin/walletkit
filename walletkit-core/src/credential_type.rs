use strum::EnumString;

use crate::Environment;

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Object, EnumString, Hash)]
#[strum(serialize_all = "snake_case")]
pub enum CredentialType {
    Orb,
    Passport,
    SecurePassport,
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
            Environment::Production => match self {
                Self::Orb => "https://signup-orb-ethereum.stage-crypto.worldcoin.org",
                Self::Device => {
                    "https://signup-phone-ethereum.stage-crypto.worldcoin.org"
                }
                Self::Passport => "https://signup-document.stage-crypto.worldcoin.org",
                Self::SecurePassport => {
                    "https://signup-document-secure.stage-crypto.worldcoin.org"
                }
            },
            Environment::Staging => match self {
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
