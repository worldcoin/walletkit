//! Flamingo request validation on all targets and attested matching on native targets.
//!
//! Browser callers can validate capture inputs before opening a session. The current
//! verifier client uses native WebSocket networking, so matching remains native-only.
//! Input validation does not decode images, verify attestation, or establish a match.

mod errors;
#[cfg(not(target_arch = "wasm32"))]
mod matcher;
mod types;
#[cfg(not(target_arch = "wasm32"))]
mod verified;

pub use errors::{
    FlamingoComparison, FlamingoError, FlamingoImageFailureReason, FlamingoImageRole,
    FlamingoMatchRejection,
};
#[cfg(not(target_arch = "wasm32"))]
pub use matcher::FlamingoMatcher;
pub use types::{FlamingoLiveCapture, FlamingoMatchRequest, FlamingoMatchingFrame};
#[cfg(not(target_arch = "wasm32"))]
pub use verified::{FlamingoMatchOutcome, VerifiedMatchToken};

/// Checks request byte limits and the normalized similarity threshold without networking.
///
/// This does not verify image contents, PCP hashes, attestation, or a biometric result.
///
/// # Errors
/// Returns [`FlamingoError::InvalidInput`] for empty or oversized fields, excessive
/// combined image size, or a non-finite/out-of-range threshold.
#[uniffi::export]
pub fn validate_flamingo_match_request(
    request: FlamingoMatchRequest,
) -> Result<(), FlamingoError> {
    request.validate()
}
