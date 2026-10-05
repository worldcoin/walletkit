/**
 * Messages between the page and the dedicated worker that owns the WASM module.
 *
 * Rust objects cannot cross `postMessage`, so the worker keeps them in a handle table
 * and the page holds opaque `Ref`s. Everything else is plain structured-clone data.
 */

/** Exported Rust classes, named as in the Swift and Kotlin bindings. */
export const CLASS_NAMES = [
  "Authenticator",
  "InitializingAuthenticator",
  "CredentialStore",
  "StorageKeys",
  "StoragePaths",
  "EmbeddedZkArtifacts",
  "FieldElement",
  "Credential",
  "ProofRequest",
  "ProofResponse",
] as const;
export type ClassName = (typeof CLASS_NAMES)[number];

/** Exported Rust free functions. */
export const FUNCTION_NAMES = [
  "recoveryDataFromSeed",
  "validateAuthenticatorPubkey",
  "checkCredentialsAgainstProofRequest",
  "pohRecoveryAgentAddress",
  "worldIdVerifierAddress",
] as const;
export type FunctionName = (typeof FUNCTION_NAMES)[number];

export type Handle = number;

/** A Rust object owned by the worker. */
export interface Ref {
  $ref: Handle;
  class: ClassName;
}

export type Target =
  | { function: FunctionName }
  | { class: ClassName; construct: true }
  | { class: ClassName; static: string }
  | { handle: Handle; method: string };

export type Request = { id: number } & (
  | { op: "initialize"; wasmUrl: string }
  | { op: "call"; target: Target; args: unknown[] }
  | { op: "release"; handle: Handle }
  | { op: "close" }
);

export type Response = { id: number } & (
  | { ok: true; result: unknown }
  | { ok: false; error: { name: string; message: string } }
);
