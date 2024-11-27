use strum::EnumString;

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
}
