//! Flamingo face matching.

use crate::native::{codec::Binary, error::Result, operation::Operation};
use std::{collections::HashMap, sync::Arc};
use walletkit_core::flamingo::{
    FlamingoMatchOutcome, FlamingoMatchRequest, FlamingoMatcher,
    RequestIntegrityProvider, VerifiedMatchToken,
};
#[cfg(feature = "jni")]
use walletkit_jni_macros::jni_export;

/// `VerifiedMatchToken.matchCoefficient`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn verified_match_token_match_coefficient(token: Arc<VerifiedMatchToken>) -> f32 {
    token.match_coefficient()
}

/// `FlamingoMatcher.create`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn flamingo_matcher_new(host_url: String) -> Result<Arc<FlamingoMatcher>> {
    Ok(Arc::new(FlamingoMatcher::new(&host_url)?))
}

/// `FlamingoMatcher.newAttested`. The provider is retained by the matcher.
#[cfg_attr(feature = "jni", jni_export)]
pub fn flamingo_matcher_new_attested(
    host_url: String,
    integrity_provider: Arc<dyn RequestIntegrityProvider>,
) -> Result<Arc<FlamingoMatcher>> {
    Ok(Arc::new(FlamingoMatcher::new_attested(
        &host_url,
        integrity_provider,
    )?))
}

/// `FlamingoMatcher.withMeasurements`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn flamingo_matcher_with_measurements(
    matcher: Arc<FlamingoMatcher>,
    measurements: Binary<HashMap<u32, Vec<u8>>>,
) -> Result<Arc<FlamingoMatcher>> {
    Ok(Arc::new(matcher.with_measurements(measurements.0)?))
}

/// `FlamingoMatcher.dangerouslySkipMeasurements`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn flamingo_matcher_dangerously_skip_measurements(
    matcher: Arc<FlamingoMatcher>,
) -> Result<Arc<FlamingoMatcher>> {
    Ok(Arc::new(matcher.dangerously_skip_measurements()?))
}

/// `FlamingoMatcher.withHeaders`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn flamingo_matcher_with_headers(
    matcher: Arc<FlamingoMatcher>,
    headers: Binary<HashMap<String, String>>,
) -> Result<Arc<FlamingoMatcher>> {
    Ok(Arc::new(matcher.with_headers(headers.0)?))
}

/// `FlamingoMatcher.performMatch`. A matched outcome transfers a token handle.
#[cfg_attr(feature = "jni", jni_export)]
pub fn flamingo_matcher_perform_match(
    operation: Operation,
    matcher: Arc<FlamingoMatcher>,
    request: Binary<FlamingoMatchRequest>,
) -> Result<Binary<FlamingoMatchOutcome>> {
    operation.run(async move { Ok(Binary(matcher.perform_match(request.0).await?)) })
}
