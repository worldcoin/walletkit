use std::sync::Arc;

use flamingo_verifier_client::{RequestContext, VerifiedMatch, VerifiedMatchResult};
use flamingo_verifier_sealed_types::{
    DebugReport, Entry, FailureReason, InputFailureReason, Payload,
};

use super::engine::{EngineConfiguration, FlamingoEngineConfiguration, SelectedEngine};
use super::errors::{FlamingoError, FlamingoInputFailureKind, FlamingoMatchRejection};
use crate::FieldElement;

/// A WIP-201 request: the Relying Party's binding and offer, and the Engine inputs.
///
/// The Verifier interprets none of `entries`, `compare` or `hints`. The chosen pipeline gives each
/// `compare` position its role, and its release manifest describes the layout. A Proof of Embedding
/// Similarity (WIP-202) requires the Credential image, the live capture and the challenge at
/// `compare` positions 0, 1 and 2.
///
/// Entry buffers move into the request without being copied.
#[derive(uniffi::Record)]
pub struct FlamingoMatchRequest {
    /// The RP's `rpId`.
    pub aud: Arc<FieldElement>,
    /// The RP's single-use nonce; must be nonzero.
    pub nonce: Arc<FieldElement>,
    /// Engine configurations the RP accepts, most preferred first.
    pub offered_configurations: Vec<FlamingoEngineConfiguration>,
    /// Inputs to the Engine, at most 8.
    pub entries: Vec<FlamingoEntry>,
    /// Two to four distinct indices into `entries`; position `k` becomes `compared_entry_hash_k`.
    pub compare: Vec<u8>,
    /// Request-level Engine hints, at most 1 KiB.
    pub hints: Vec<u8>,
}

/// One Engine input.
#[derive(uniffi::Record)]
pub struct FlamingoEntry {
    /// An encoded image or an embedding.
    pub data: Vec<u8>,
    /// How the Engine reads `data`, at most 256 bytes; defined by the pipeline.
    pub meta: Vec<u8>,
}

/// A request whose fields passed every WIP-201 bound, ready to be bound to a session's Engine.
pub(super) struct PreparedRequest {
    pub offer: Vec<EngineConfiguration>,
    context: RequestContext,
    payload: Payload,
}

impl FlamingoMatchRequest {
    /// Checks the request against the WIP-201 bounds before anything is sent.
    pub(super) fn prepare(self) -> Result<PreparedRequest, FlamingoError> {
        let offer = self
            .offered_configurations
            .iter()
            .map(EngineConfiguration::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        let Some(first) = offer.first() else {
            return Err(FlamingoError::invalid_shape(
                "offered_configurations",
                "must not be empty",
            ));
        };
        let nonce = self.nonce.to_be_bytes();
        if nonce == [0; 32] {
            return Err(FlamingoError::invalid_shape("nonce", "must be nonzero"));
        }

        let payload = Payload {
            hints: self.hints.into(),
            compare: self.compare,
            entries: self
                .entries
                .into_iter()
                .map(|entry| Entry {
                    data: entry.data.into(),
                    meta: entry.meta.into(),
                })
                .collect(),
            pipeline: first.pipeline,
            engine_hash: [0; 32].into(),
            match_strictness: first.match_strictness,
        };
        payload.validate().map_err(payload_error)?;

        Ok(PreparedRequest {
            offer,
            context: RequestContext {
                aud: self.aud.to_be_bytes(),
                nonce,
                aat_inputs: None,
            },
            payload,
        })
    }
}

impl PreparedRequest {
    /// Binds the payload to the Engine chosen on one session.
    pub(super) fn bind(
        &mut self,
        engine: &SelectedEngine,
    ) -> (&Payload, &RequestContext) {
        self.payload.pipeline = engine.configuration.pipeline;
        self.payload.match_strictness = engine.configuration.match_strictness;
        self.payload.engine_hash = engine.engine_hash.into();
        (&self.payload, &self.context)
    }
}

fn payload_error(reason: FailureReason) -> FlamingoError {
    let (kind, limit_bytes) = match reason {
        FailureReason::InputRejected {
            reason: InputFailureReason::ImageTooLarge,
            limit_bytes,
            ..
        } => (FlamingoInputFailureKind::TooLarge, limit_bytes),
        FailureReason::InputRejected {
            reason: InputFailureReason::TotalImagesTooLarge,
            limit_bytes,
            ..
        } => (FlamingoInputFailureKind::TotalTooLarge, limit_bytes),
        _ => {
            return FlamingoError::invalid_shape(
                "payload",
                "entries, compare, meta or hints violate a WIP-201 bound",
            )
        }
    };
    FlamingoError::InvalidInput {
        attribute: "entries".to_string(),
        reason: format!("must not exceed {} bytes", limit_bytes.unwrap_or_default()),
        kind,
        limit_bytes,
    }
}

/// A Flamingo Token whose signing-key attestation, signature and claims were verified.
///
/// The claims equal those the request implies: its `aud` and `nonce`, the hashes of the compared
/// entries and the chosen Engine configuration. Foreign callers receive an opaque handle; the token
/// and its signing-key attestation stay together in Rust for proof generation and for relaying the
/// attestation to the RP.
#[derive(Debug, uniffi::Object)]
pub struct VerifiedFlamingoToken {
    token: Vec<u8>,
    signing_key_attestation: Vec<u8>,
}

impl VerifiedFlamingoToken {
    /// Borrows the encoded CWT for proof generation.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.token
    }

    /// Borrows the signing-key attestation every proof relying on the token must carry.
    #[must_use]
    pub fn signing_key_attestation(&self) -> &[u8] {
        &self.signing_key_attestation
    }
}

impl From<VerifiedMatch> for VerifiedFlamingoToken {
    fn from(value: VerifiedMatch) -> Self {
        Self {
            token: value.statement.token.into_bytes(),
            signing_key_attestation: value.statement.signing_key_attestation,
        }
    }
}

/// The outcome of a Flamingo request.
#[derive(Debug, uniffi::Enum)]
pub enum FlamingoMatchOutcome {
    /// The Engine passed, and `WalletKit` verified the Flamingo Token.
    Matched {
        /// Verified token handle for proof consumers.
        token: Arc<VerifiedFlamingoToken>,
        /// The offered configuration the Verifier ran.
        configuration: FlamingoEngineConfiguration,
        /// Engine diagnostics, not covered by the token.
        debug_report: FlamingoDebugReport,
    },
    /// The response reported a rejection. An unsigned rejection does not authenticate its sender.
    Rejected {
        /// Structured input or biometric rejection.
        reason: FlamingoMatchRejection,
        /// Engine diagnostics, if produced before rejection.
        debug_report: FlamingoDebugReport,
    },
}

impl FlamingoMatchOutcome {
    pub(super) fn new(
        result: VerifiedMatchResult,
        configuration: EngineConfiguration,
    ) -> Self {
        match result {
            VerifiedMatchResult::Success {
                verified,
                debug_report,
            } => Self::Matched {
                token: Arc::new(VerifiedFlamingoToken::from(*verified)),
                configuration: configuration.into(),
                debug_report: debug_report.into(),
            },
            VerifiedMatchResult::Failed {
                reason,
                debug_report,
            } => Self::Rejected {
                reason: reason.into(),
                debug_report: debug_report.into(),
            },
        }
    }
}

/// Engine diagnostic delivery status. JSON is excluded from `Debug` output.
///
/// A report may describe biometric data. It must not be forwarded without the user's explicit
/// consent, and then only to the Engine Provider.
#[derive(Clone, PartialEq, Eq, uniffi::Enum)]
pub enum FlamingoDebugReport {
    /// Original Engine JSON without reserialization.
    Available {
        /// Bounded original UTF-8 JSON.
        json: String,
    },
    /// The Engine did not produce a report, or did not run.
    NotProduced,
    /// Entire report omitted while preserving the outcome.
    OmittedTooLarge {
        /// Original UTF-8 byte count.
        original_size_bytes: u64,
    },
}

impl std::fmt::Debug for FlamingoDebugReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Available { json } => f
                .debug_struct("Available")
                .field("bytes", &json.len())
                .finish(),
            Self::NotProduced => f.write_str("NotProduced"),
            Self::OmittedTooLarge {
                original_size_bytes,
            } => f
                .debug_struct("OmittedTooLarge")
                .field("original_size_bytes", original_size_bytes)
                .finish(),
        }
    }
}

impl From<DebugReport> for FlamingoDebugReport {
    fn from(value: DebugReport) -> Self {
        match value {
            DebugReport::Available { json } => Self::Available { json },
            DebugReport::NotProduced => Self::NotProduced,
            DebugReport::OmittedTooLarge {
                original_size_bytes,
            } => Self::OmittedTooLarge {
                original_size_bytes,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{
        FlamingoEngineConfiguration, FlamingoEntry, FlamingoError,
        FlamingoInputFailureKind, FlamingoMatchRequest, SelectedEngine,
    };
    use crate::flamingo::engine::EngineConfiguration;
    use crate::FieldElement;

    fn request(entries: Vec<FlamingoEntry>, compare: Vec<u8>) -> FlamingoMatchRequest {
        FlamingoMatchRequest {
            aud: Arc::new(FieldElement::from(1_928_118)),
            nonce: Arc::new(FieldElement::from(42)),
            offered_configurations: vec![FlamingoEngineConfiguration {
                release_hash: vec![0x2a; 32],
                pipeline: 1,
                match_strictness: 2,
            }],
            entries,
            compare,
            hints: Vec::new(),
        }
    }

    fn entry(data: Vec<u8>) -> FlamingoEntry {
        FlamingoEntry {
            data,
            meta: Vec::new(),
        }
    }

    #[test]
    fn binds_the_session_engine_and_moves_entry_buffers() {
        let credential = vec![1; 1024];
        let pointer = credential.as_ptr();
        let mut prepared = request(
            vec![entry(credential), entry(vec![2]), entry(vec![3])],
            vec![0, 1, 2],
        )
        .prepare()
        .unwrap();
        let engine = SelectedEngine {
            configuration: EngineConfiguration {
                release_hash: [0x2a; 32],
                pipeline: 3,
                match_strictness: 1,
            },
            engine_hash: [0x11; 32],
        };
        let (payload, context) = prepared.bind(&engine);
        assert_eq!(context.aud[29..], [0x1d, 0x6b, 0xb6]);
        assert_eq!(context.nonce[31], 42);
        assert!(context.aat_inputs.is_none());
        assert_eq!(payload.pipeline, 3);
        assert_eq!(payload.match_strictness, 1);
        assert_eq!(*payload.engine_hash, [0x11; 32]);
        assert_eq!(payload.entries[0].data.as_ptr(), pointer);
    }

    #[test]
    fn rejects_requests_outside_the_wip_201_bounds() {
        let mut empty_offer = request(vec![entry(vec![1]), entry(vec![2])], vec![0, 1]);
        empty_offer.offered_configurations.clear();
        let mut zero_nonce = request(vec![entry(vec![1]), entry(vec![2])], vec![0, 1]);
        zero_nonce.nonce = Arc::new(FieldElement::from(0));
        let mut short_release =
            request(vec![entry(vec![1]), entry(vec![2])], vec![0, 1]);
        short_release.offered_configurations[0].release_hash = vec![0x2a; 31];
        let mut long_hints = request(vec![entry(vec![1]), entry(vec![2])], vec![0, 1]);
        long_hints.hints = vec![0; 1025];

        for (request, attribute) in [
            (empty_offer, "offered_configurations"),
            (zero_nonce, "nonce"),
            (short_release, "release_hash"),
            (request(vec![entry(vec![1])], vec![0]), "payload"),
            (
                request(vec![entry(vec![1]), entry(vec![2])], vec![0, 0]),
                "payload",
            ),
            (
                request(vec![entry(vec![1]), entry(vec![2])], vec![0, 2]),
                "payload",
            ),
            (
                request((0..9).map(|_| entry(vec![1])).collect(), vec![0, 1]),
                "payload",
            ),
            (long_hints, "payload"),
        ] {
            let Err(FlamingoError::InvalidInput {
                attribute: actual,
                kind,
                ..
            }) = request.prepare()
            else {
                panic!("{attribute} should be rejected");
            };
            assert_eq!(actual, attribute);
            assert_eq!(kind, FlamingoInputFailureKind::InvalidShape);
        }
    }

    #[test]
    fn reports_the_exceeded_entry_budget() {
        use flamingo_verifier_api_types::{MAX_ENTRY_BYTES, MAX_TOTAL_ENTRY_BYTES};

        for (entries, kind, limit) in [
            (
                vec![entry(vec![0; MAX_ENTRY_BYTES + 1]), entry(vec![1])],
                FlamingoInputFailureKind::TooLarge,
                MAX_ENTRY_BYTES,
            ),
            (
                vec![
                    entry(vec![0; MAX_ENTRY_BYTES]),
                    entry(vec![1; MAX_TOTAL_ENTRY_BYTES - MAX_ENTRY_BYTES + 1]),
                ],
                FlamingoInputFailureKind::TotalTooLarge,
                MAX_TOTAL_ENTRY_BYTES,
            ),
        ] {
            let Err(FlamingoError::InvalidInput {
                kind: actual,
                limit_bytes,
                ..
            }) = request(entries, vec![0, 1]).prepare()
            else {
                panic!("an entry budget should be enforced");
            };
            assert_eq!(actual, kind);
            assert_eq!(limit_bytes, Some(limit as u64));
        }
    }
}
