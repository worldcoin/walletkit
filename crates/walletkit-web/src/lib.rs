//! Browser facade over `walletkit-core`, exported with `wasm-bindgen`.
//!
//! The `@worldcoin/walletkit-web` npm package runs this module inside a dedicated Web Worker.
//! The exported classes and functions mirror the `UniFFI` objects that the Swift and
//! Kotlin bindings expose (`Authenticator`, `InitializingAuthenticator`,
//! `CredentialStore`, …) with the same names and arguments, in `camelCase`.
//!
//! Rust objects never cross into the page: the worker keeps them and hands the page
//! opaque handles. Records, such as registration status or credential records, are
//! returned as plain structured-clone data. Only the surface the browser can serve is
//! exported: there are no foreign traits or callbacks. Vault backup export and
//! replacement import, change listeners and credential ownership proofs are
//! native-only in core.

#![cfg(all(target_arch = "wasm32", target_os = "unknown"))]

mod authenticator;
mod error;
mod issuers;
mod js;
mod storage;
mod values;

use std::sync::Arc;

use js_sys::BigInt;
use walletkit_core::{
    authenticator::recovery_data_from_seed,
    logger::{emit_log, init_logging, sanitize_hex_secrets, LogLevel},
    proof_request_credential_constraints_check::{
        check_credentials_against_proof_request, CredentialConstraintsCheckResult,
    },
};
use wasm_bindgen::prelude::*;

use crate::{
    error::{invalid_argument, to_js},
    storage::JsCredentialStore,
    values::JsProofRequest,
};

#[wasm_bindgen(typescript_custom_section)]
const TS_TYPES: &str = r#"
export type Environment = "production" | "staging";
export type Region = "eu" | "us" | "ap";
export type LogLevel = "trace" | "debug" | "info" | "warn" | "error";

export interface RecoveryData {
  authenticatorAddress: string;
  authenticatorPubkey: string;
  offchainSignerCommitment: string;
}

export interface RecoveryUpdateSignature {
  signature: Uint8Array;
  /** 0x-prefixed, zero-padded 256-bit hex string. */
  nonce: string;
}

export type RegistrationStatus =
  | { state: "queued" | "batching" | "submitted" | "finalized" }
  | { state: "failed"; error: string; errorCode?: string };

export type GatewayRequestStatus =
  | { state: "queued" | "batching" }
  | { state: "submitted" | "finalized"; txHash: string }
  | { state: "failed"; error: string; errorCode?: string };

export interface CredentialRecord {
  credentialId: bigint;
  issuerSchemaId: bigint;
  genesisIssuedAt: bigint;
  expiresAt: bigint;
  isExpired: boolean;
}

export type ActivityOutcome =
  | "completed"
  | "declined"
  | "cancelled"
  | "failed"
  | "incomplete";

export type ActivityFailureReason =
  | "networkerror"
  | "timeout"
  | "deviceauthenticationfailed"
  | "proofgenerationfailed"
  | "relyingpartyrejected";

export interface ActivityEntry {
  id?: bigint;
  rpId: bigint;
  appIdentifier: string;
  clientId: string;
  /** World ID protocol version. */
  protocol: 3 | 4;
  timestamp?: bigint;
  outcome: ActivityOutcome;
  issuerSchemaIds: bigint[];
  failureReason?: ActivityFailureReason;
}

export interface ActivityMetadata {
  totalCount: bigint;
}

export interface CredentialConstraintsCheckItem {
  identifier: string;
  issuerSchemaId: bigint;
  hasCredential: boolean;
}

export interface CredentialConstraintsCheckResult {
  isSatisfied: boolean;
  checkResults: CredentialConstraintsCheckItem[];
}
"#;

/// Forwards Rust panics to the console before the module traps.
///
/// A panic leaves the instance unusable; the worker reports the resulting
/// `WebAssembly.RuntimeError` and refuses further calls.
#[wasm_bindgen(start)]
fn start() {
    std::panic::set_hook(Box::new(|info| {
        js::console_error(&sanitize_hex_secrets(info.to_string()));
    }));
    init_logging(Arc::new(js::ConsoleLogger), Some(LogLevel::Warn));
}

/// Replaces hex sequences long enough to be secrets with a redacted form that keeps
/// only the first and last two digits.
#[wasm_bindgen(js_name = sanitizeHexSecrets)]
#[must_use]
pub fn sanitize_hex_secrets_js(input: String) -> String {
    sanitize_hex_secrets(input)
}

/// Emits `message` through `WalletKit`'s logging pipeline, to check that it is wired up.
///
/// The worker writes warnings and errors to its console; lower levels are dropped.
///
/// # Errors
/// Throws a `TypeError` for an unknown level.
#[wasm_bindgen(js_name = emitLog)]
pub fn emit_log_js(
    #[wasm_bindgen(unchecked_param_type = "LogLevel")] level: &str,
    message: String,
) -> Result<(), JsValue> {
    let level = match level {
        "trace" => LogLevel::Trace,
        "debug" => LogLevel::Debug,
        "info" => LogLevel::Info,
        "warn" => LogLevel::Warn,
        "error" => LogLevel::Error,
        _ => return Err(invalid_argument(&format!("Unknown log level: {level}"))),
    };
    emit_log(level, message);
    Ok(())
}

/// Derives the recovery identity material for a 32-byte seed.
///
/// # Errors
/// Throws a `WalletKitError` when the seed is invalid.
#[wasm_bindgen(js_name = recoveryDataFromSeed, unchecked_return_type = "RecoveryData")]
pub fn recovery_data_from_seed_js(seed: Vec<u8>) -> Result<JsValue, JsValue> {
    let data = recovery_data_from_seed(seed).map_err(to_js)?;
    js::object(&[
        ("authenticatorAddress", data.authenticator_address.into()),
        ("authenticatorPubkey", data.authenticator_pubkey.into()),
        (
            "offchainSignerCommitment",
            data.offchain_signer_commitment.into(),
        ),
    ])
}

/// Checks whether the stored, unexpired credentials can satisfy `request`.
///
/// # Errors
/// Throws a `CredentialConstraintsCheckError` when the constraints are too deep or too
/// large, or a `StorageError` when the vault cannot be read.
#[wasm_bindgen(js_name = checkCredentialsAgainstProofRequest, unchecked_return_type = "CredentialConstraintsCheckResult")]
pub fn check_credentials_against_proof_request_js(
    request: &JsProofRequest,
    store: &JsCredentialStore,
    now: BigInt,
) -> Result<JsValue, JsValue> {
    let now = js::u64_arg("now", now)?;
    let CredentialConstraintsCheckResult {
        is_satisfied,
        check_results,
    } = check_credentials_against_proof_request(&request.0, &store.0, now)
        .map_err(to_js)?;
    let check_results = check_results
        .iter()
        .map(|item| {
            js::object(&[
                ("identifier", item.identifier.as_str().into()),
                ("issuerSchemaId", item.issuer_schema_id.into()),
                ("hasCredential", item.has_credential.into()),
            ])
        })
        .collect::<Result<Vec<_>, _>>()?;
    js::object(&[
        ("isSatisfied", is_satisfied.into()),
        ("checkResults", js::array(check_results)),
    ])
}
