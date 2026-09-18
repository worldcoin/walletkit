use std::sync::Arc;

use flamingo_verifier_client::VerifiedMatch;
use flamingo_verifier_protocol::match_token::MatchClaims;
use flamingo_verifier_sealed_types::{
    DeepFaceInputs, GrayBadgeInputs, LiveCapture, MatchInputs,
};

use super::errors::FlamingoMatchRejection;

/// Explicit operation-specific inputs. Image buffers move into the client without cloning.
#[derive(uniffi::Enum)]
pub enum FlamingoMatchRequest {
    /// Three-way matching with the exact original Orb PCP hashes.json.
    DeepFace {
        /// Exact encoded Orb thumbnail bytes.
        orb_credential: Vec<u8>,
        /// Explicit live capture variant.
        live: FlamingoLiveCapture,
        /// Exact encoded RTMS challenge bytes.
        rtms_challenge: Vec<u8>,
        /// Original PCP hashes.json bytes.
        hashes_json: Vec<u8>,
        /// Minimum normalized cosine similarity in [0, 1].
        match_threshold: f64,
    },
    /// Live/challenge matching without credential fields.
    /// Currently rejected by Flamingo 0.4.0 as an unsupported operation.
    GrayBadge {
        /// Explicit live capture variant.
        live: FlamingoLiveCapture,
        /// Exact encoded RTMS challenge bytes.
        rtms_challenge: Vec<u8>,
        /// Minimum normalized cosine similarity in [0, 1].
        match_threshold: f64,
    },
}

/// A single image or an explicitly selected `LightGuard` pair.
#[derive(uniffi::Enum)]
pub enum FlamingoLiveCapture {
    /// Vanilla selfie bytes.
    Vanilla {
        /// Encoded vanilla selfie bytes.
        image: Vec<u8>,
    },
    /// Both `LightGuard` frames; rejected explicitly by backends without `LightGuard`.
    LightGuard {
        /// Illuminated frame bytes.
        illuminated: Vec<u8>,
        /// Unilluminated frame bytes.
        unilluminated: Vec<u8>,
        /// Frame used for matching.
        matching_frame: FlamingoMatchingFrame,
    },
}

/// Which `LightGuard` frame provides the matching embedding.
#[derive(Debug, Clone, Copy, uniffi::Enum)]
pub enum FlamingoMatchingFrame {
    /// Use the illuminated frame.
    Illuminated,
    /// Use the unilluminated frame.
    Unilluminated,
}

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

impl FlamingoMatchRequest {
    pub(super) fn into_inputs(self) -> MatchInputs {
        match self {
            Self::DeepFace {
                orb_credential,
                live,
                rtms_challenge,
                hashes_json,
                match_threshold,
            } => MatchInputs::DeepFace(DeepFaceInputs {
                orb_credential: orb_credential.into(),
                live: live.into(),
                rtms_challenge: rtms_challenge.into(),
                hashes_json: hashes_json.into(),
                match_threshold,
            }),
            Self::GrayBadge {
                live,
                rtms_challenge,
                match_threshold,
            } => MatchInputs::GrayBadge(GrayBadgeInputs {
                live: live.into(),
                rtms_challenge: rtms_challenge.into(),
                match_threshold,
            }),
        }
    }
}
impl From<FlamingoLiveCapture> for LiveCapture {
    fn from(value: FlamingoLiveCapture) -> Self {
        match value {
            FlamingoLiveCapture::Vanilla { image } => Self::Vanilla(image.into()),
            FlamingoLiveCapture::LightGuard { illuminated, unilluminated, matching_frame } => Self::LightGuard {
                illuminated: illuminated.into(), unilluminated: unilluminated.into(),
                matching_frame: match matching_frame {
                    FlamingoMatchingFrame::Illuminated => flamingo_verifier_sealed_types::LightGuardMatchingFrame::Illuminated,
                    FlamingoMatchingFrame::Unilluminated => flamingo_verifier_sealed_types::LightGuardMatchingFrame::Unilluminated,
                },
            },
        }
    }
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

#[cfg(test)]
mod tests {
    use super::{FlamingoLiveCapture, FlamingoMatchRequest, MatchInputs};

    #[test]
    fn gray_badge_has_no_pcp_and_moves_image_buffers() {
        let image = vec![1; 1024];
        let pointer = image.as_ptr();
        let request = FlamingoMatchRequest::GrayBadge {
            live: FlamingoLiveCapture::Vanilla { image },
            rtms_challenge: vec![2; 512],
            match_threshold: 0.5,
        }
        .into_inputs();
        request.validate().unwrap();
        let encoded = request.to_cbor().unwrap();
        assert!(matches!(
            MatchInputs::from_cbor(&encoded),
            Ok(MatchInputs::GrayBadge(_))
        ));
        let MatchInputs::GrayBadge(inputs) = request else {
            unreachable!()
        };
        let flamingo_verifier_sealed_types::LiveCapture::Vanilla(image) = inputs.live
        else {
            unreachable!()
        };
        assert_eq!(image.as_ptr(), pointer);
    }
}
