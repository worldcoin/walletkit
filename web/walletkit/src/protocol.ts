/** Values crossing the worker boundary are plain structured-clone data. */
export interface RecoveryData {
  authenticatorAddress: string;
  authenticatorPubkey: string;
  offchainSignerCommitment: string;
}
export type RegistrationStatus =
  | { state: "queued" | "batching" | "submitted" | "finalized" }
  | { state: "failed"; error: string; errorCode?: string };
export interface InitializeOptions {
  /** 32-byte database encryption key. Supply the same databaseKey when reopening storage. */
  databaseKey: Uint8Array;
  /** Stable storage namespace, unique per consumer/account. Default: "default". */
  storageId?: string;
  environment?: "production" | "staging";
  region?: "eu" | "us" | "ap";
  rpcUrl?: string;
  workerUrl?: string | URL;
  wasmUrl?: string | URL;
  /** Abort initialization and release the worker (for example on unmount). */
  signal?: AbortSignal;
}
export type WorkerOptions = Required<
  Pick<InitializeOptions, "storageId" | "environment" | "region">
> &
  Pick<InitializeOptions, "rpcUrl"> & {
    databaseKey: Uint8Array;
    wasmUrl: string;
  };
export interface Operations {
  initialize: { args: [WorkerOptions]; result: void };
  recoveryDataFromSeed: { args: [Uint8Array]; result: RecoveryData };
  register: { args: [Uint8Array]; result: void };
  pollRegistration: { args: []; result: RegistrationStatus };
  initializeAuthenticator: { args: [Uint8Array, bigint]; result: void };
  prepareCredential: {
    args: [bigint];
    result: { blindingFactor: string; sub: string };
  };
  storeCredential: {
    args: [Uint8Array, string, bigint];
    result: { credentialId: bigint; issuerSchemaId: bigint };
  };
  generateProof: { args: [string, bigint]; result: string };
  close: { args: []; result: void };
}
export type Method = keyof Operations;
export type Request = {
  [M in Method]: { id: number; method: M; args: Operations[M]["args"] };
}[Method];
export type Response = { id: number } & (
  | { ok: true; result: unknown }
  | { ok: false; error: { name: string; message: string } }
);
