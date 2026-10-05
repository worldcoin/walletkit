/**
 * Messages between the page and the dedicated worker that owns the WASM module.
 *
 * Rust objects cannot cross `postMessage`, so the worker keeps them in a handle table
 * and the page holds opaque `Ref`s. Everything else is plain structured-clone data.
 */

/**
 * Everything the page may call, named as in the Swift and Kotlin bindings.
 *
 * The worker only dispatches names listed here, so the wasm-bindgen internals on the
 * generated classes (`__wrap`, `__destroy_into_raw`, …) stay unreachable. `api.ts`
 * types its proxies against this registry.
 */
export const API = {
  Authenticator: {
    statics: ["initWithDefaults", "initWithOhttpDefaults", "init"],
    methods: [
      "initStorage",
      "destroyStorage",
      "packedAccountData",
      "leafIndex",
      "onchainAddress",
      "getPackedAccountDataRemote",
      "generateCredentialBlindingFactorRemote",
      "computeCredentialSub",
      "dangerSignChallenge",
      "dangerSignInitiateRecoveryAgentUpdate",
      "updateRecoveryAgent",
      "revertRecoveryAgentUpdate",
      "insertAuthenticator",
      "hasAuthenticatorPubkey",
      "getAuthenticatorPubkeys",
      "removeAuthenticator",
      "pollStatus",
      "generateProof",
    ],
  },
  InitializingAuthenticator: {
    statics: ["registerWithDefaults", "registerWithOhttpDefaults", "register"],
    methods: ["pollStatus"],
  },
  CredentialStore: {
    construct: true,
    statics: [],
    methods: [
      "storagePaths",
      "init",
      "listCredentials",
      "fetchCredential",
      "deleteCredential",
      "storeCredential",
      "dangerDeleteAllCredentials",
      "recordActivity",
      "listActivities",
      "activityMetadata",
      "clearActivities",
      "destroyStorage",
    ],
  },
  StorageKeys: { statics: ["fromBytes"], methods: [] },
  StoragePaths: {
    statics: ["fromRoot"],
    methods: [
      "rootPathString",
      "worldidDirPathString",
      "vaultDbPathString",
      "cacheDbPathString",
      "lockPathString",
      "groth16DirPathString",
      "queryZkeyPathString",
      "nullifierZkeyPathString",
      "queryGraphPathString",
      "nullifierGraphPathString",
    ],
  },
  EmbeddedZkArtifacts: { construct: true, statics: [], methods: [] },
  FieldElement: {
    statics: ["fromBytes", "fromU64", "tryFromHexString"],
    methods: ["toBytes", "toHexString"],
  },
  Credential: {
    statics: ["fromBytes"],
    methods: [
      "sub",
      "issuerSchemaId",
      "genesisIssuedAt",
      "expiresAt",
      "associatedDataCommitment",
      "claims",
      "claimsHex",
      "toBytes",
    ],
  },
  ProofRequest: {
    statics: ["fromJson"],
    methods: ["toJson", "id", "version"],
  },
  ProofResponse: {
    statics: [],
    methods: ["toJson", "id", "version", "error"],
  },
} as const satisfies Record<
  string,
  {
    construct?: true;
    statics: readonly string[];
    methods: readonly string[];
  }
>;
export type ClassName = keyof typeof API;
export type StaticName<C extends ClassName> =
  (typeof API)[C]["statics"][number];
export type MethodName<C extends ClassName> =
  (typeof API)[C]["methods"][number];

export const CLASS_NAMES = Object.keys(API) as ClassName[];

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
  | { ok: false; error: { name: string; message: string; code?: string } }
);
