use std::sync::Arc;

use flamingo_verifier_client::VerifiedMatch;
use flamingo_verifier_protocol::match_token::MatchClaims;

use super::FlamingoMatchRejection;

/// A match token whose signing-key attestation and signature were verified.
///
/// Foreign callers receive an opaque handle. The token and signing-key attestation remain
/// together in Rust for proof generation and eventual relay of the attestation to the RP.
#[derive(Debug, uniffi::Object)]
pub struct VerifiedMatchToken {
    token: Vec<u8>,
    claims: MatchClaims,
    signing_key_attestation: Vec<u8>,
}

/// The outcome of the TEE match phase.
#[derive(Debug, uniffi::Enum)]
pub enum FlamingoMatchOutcome {
    /// The enclave issued a token and `WalletKit` verified it against an attested signing key.
    Matched(Arc<VerifiedMatchToken>),
    /// The response reported a rejection. An unsigned rejection does not authenticate its sender.
    Rejected(FlamingoMatchRejection),
}

#[uniffi::export]
impl VerifiedMatchToken {
    /// Credential-versus-live normalized similarity authenticated by the token.
    ///
    /// The other two comparison scores and the requested threshold are not in the token.
    #[must_use]
    pub const fn match_coefficient(&self) -> f32 {
        self.claims.match_coefficient
    }
}

impl VerifiedMatchToken {
    /// Borrows the encoded COSE/CBOR token for proof generation.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.token
    }

    /// Borrows the signing-key attestation to relay alongside the generated proof.
    #[must_use]
    pub fn signing_key_attestation(&self) -> &[u8] {
        &self.signing_key_attestation
    }
}

impl From<VerifiedMatch> for VerifiedMatchToken {
    fn from(value: VerifiedMatch) -> Self {
        Self {
            token: value.statement.token.into_bytes(),
            claims: value.claims,
            signing_key_attestation: value.statement.signing_key_attestation,
        }
    }
}
