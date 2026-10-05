/**
 * Plain-data records returned by and passed to the API.
 *
 * These mirror the TypeScript declarations that `walletkit-web` (Rust) emits next to
 * the generated bindings. They are declared here as well so the published typings do
 * not depend on the generated files.
 */

export type Environment = "production" | "staging";
export type Region = "eu" | "us" | "ap";

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

/** No filters are supported yet. */
export type ActivityQuery = Record<string, never>;

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
