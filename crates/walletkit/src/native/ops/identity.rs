//! Field elements, credentials, proof requests and responses, user agents, environments,
//! and logging.

use crate::native::{codec::Binary, error::Result};
use std::sync::Arc;
use walletkit_core::{
    logger::{LogLevel, Logger},
    requests::{ProofRequest, ProofResponse},
    user_agent::{UserAgent, UserAgentBuilder},
    Credential, Environment, FieldElement, OwnershipProof,
};
#[cfg(feature = "jni")]
use walletkit_jni_macros::jni_export;

/// `FieldElement.fromBytes`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn field_element_from_bytes(bytes: Vec<u8>) -> Result<Arc<FieldElement>> {
    Ok(Arc::new(FieldElement::from_bytes(bytes)?))
}

/// `FieldElement.fromU64`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn field_element_from_u64(value: u64) -> Arc<FieldElement> {
    Arc::new(FieldElement::from_u64(value))
}

/// `FieldElement.tryFromHexString`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn field_element_try_from_hex_string(
    hex_string: String,
) -> Result<Arc<FieldElement>> {
    Ok(Arc::new(FieldElement::try_from_hex_string(&hex_string)?))
}

/// `FieldElement.toBytes`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn field_element_to_bytes(element: Arc<FieldElement>) -> Vec<u8> {
    element.to_bytes()
}

/// `FieldElement.toHexString`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn field_element_to_hex_string(element: Arc<FieldElement>) -> String {
    element.to_hex_string()
}

/// `Credential.fromBytes`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn credential_from_bytes(bytes: Vec<u8>) -> Result<Arc<Credential>> {
    Ok(Arc::new(Credential::from_bytes(bytes)?))
}

/// `Credential.sub`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn credential_sub(credential: Arc<Credential>) -> Arc<FieldElement> {
    Arc::new(credential.sub())
}

/// `Credential.issuerSchemaId`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn credential_issuer_schema_id(credential: Arc<Credential>) -> u64 {
    credential.issuer_schema_id()
}

/// `Credential.expiresAt`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn credential_expires_at(credential: Arc<Credential>) -> u64 {
    credential.expires_at()
}

/// `Credential.associatedDataCommitment`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn credential_associated_data_commitment(
    credential: Arc<Credential>,
) -> Arc<FieldElement> {
    Arc::new(credential.associated_data_commitment())
}

/// `Credential.claims`: a list of new `FieldElement` handles.
#[cfg_attr(feature = "jni", jni_export)]
pub fn credential_claims(
    credential: Arc<Credential>,
) -> Binary<Vec<Arc<FieldElement>>> {
    Binary(credential.claims())
}

/// `Credential.claimsHex`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn credential_claims_hex(credential: Arc<Credential>) -> Binary<Vec<String>> {
    Binary(credential.claims_hex())
}

/// `ProofRequest.fromJson`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn proof_request_from_json(json: String) -> Result<Arc<ProofRequest>> {
    Ok(Arc::new(ProofRequest::from_json(&json)?))
}

/// `ProofRequest.toJson`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn proof_request_to_json(request: Arc<ProofRequest>) -> Result<String> {
    Ok(request.to_json()?)
}

/// `ProofRequest.id`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn proof_request_id(request: Arc<ProofRequest>) -> String {
    request.id()
}

/// `ProofRequest.version`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn proof_request_version(request: Arc<ProofRequest>) -> u8 {
    request.version()
}

/// `ProofResponse.toJson`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn proof_response_to_json(response: Arc<ProofResponse>) -> Result<String> {
    Ok(response.to_json()?)
}

/// `ProofResponse.id`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn proof_response_id(response: Arc<ProofResponse>) -> String {
    response.id()
}

/// `ProofResponse.version`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn proof_response_version(response: Arc<ProofResponse>) -> u8 {
    response.version()
}

/// `ProofResponse.error`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn proof_response_error(response: Arc<ProofResponse>) -> Option<String> {
    response.error()
}

/// `OwnershipProof.encode`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn ownership_proof_encode(proof: Arc<OwnershipProof>) -> Result<Vec<u8>> {
    Ok(proof.encode()?)
}

/// `OwnershipProof.encodeB64`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn ownership_proof_encode_b64(proof: Arc<OwnershipProof>) -> Result<String> {
    Ok(proof.encode_b64()?)
}

/// `OwnershipProof.merkleRoot`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn ownership_proof_merkle_root(proof: Arc<OwnershipProof>) -> Arc<FieldElement> {
    Arc::new(proof.merkle_root())
}

/// `UserAgent.headerValue`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn user_agent_header_value(user_agent: Arc<UserAgent>) -> String {
    user_agent.header_value()
}

/// `UserAgentBuilder.create`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn user_agent_builder_new() -> Arc<UserAgentBuilder> {
    Arc::new(UserAgentBuilder::new())
}

/// `UserAgentBuilder.withSegment`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn user_agent_builder_with_segment(
    builder: Arc<UserAgentBuilder>,
    name: String,
    version: String,
) -> Arc<UserAgentBuilder> {
    Arc::new(builder.with_segment(&name, &version))
}

/// `UserAgentBuilder.withAppSegmentForClient`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn user_agent_builder_with_app_segment_for_client(
    builder: Arc<UserAgentBuilder>,
    app_version: String,
    client_name: String,
) -> Arc<UserAgentBuilder> {
    Arc::new(builder.with_app_segment_for_client(&app_version, &client_name))
}

/// `UserAgentBuilder.withWalletkitSegment`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn user_agent_builder_with_walletkit_segment(
    builder: Arc<UserAgentBuilder>,
) -> Arc<UserAgentBuilder> {
    Arc::new(builder.with_walletkit_segment())
}

/// `UserAgentBuilder.withClientSegment`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn user_agent_builder_with_client_segment(
    builder: Arc<UserAgentBuilder>,
    client_name: String,
    os_version: String,
) -> Arc<UserAgentBuilder> {
    Arc::new(builder.with_client_segment(&client_name, &os_version))
}

/// `UserAgentBuilder.build`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn user_agent_builder_build(builder: Arc<UserAgentBuilder>) -> Arc<UserAgent> {
    Arc::new(builder.build())
}

/// `Environment.pohRecoveryAgentAddress`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn environment_poh_recovery_agent_address(environment: Environment) -> String {
    environment.poh_recovery_agent_address()
}

/// `Environment.worldIdVerifierAddress`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn environment_world_id_verifier_address(environment: Environment) -> String {
    environment.world_id_verifier_address()
}

/// `emitLog`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn emit_log(level: LogLevel, message: String) {
    walletkit_core::logger::emit_log(level, message);
}

/// `initLogging`. The logger is called on the threads that emit logs.
#[cfg_attr(feature = "jni", jni_export)]
pub fn init_logging(logger: Arc<dyn Logger>, level: Option<LogLevel>) {
    walletkit_core::logger::init_logging(logger, level);
}

/// `sanitizeHexSecrets`.
#[cfg_attr(feature = "jni", jni_export)]
pub fn sanitize_hex_secrets(input: String) -> String {
    walletkit_core::logger::sanitize_hex_secrets(input)
}
