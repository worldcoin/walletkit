/**
 * Page-side proxies for the Rust objects owned by the worker.
 *
 * The classes, methods and arguments mirror the `walletkit-core` UniFFI objects
 * that the Swift and Kotlin bindings expose, in `camelCase`. Every call is
 * asynchronous because it crosses to the worker. Objects live in the worker until
 * `free()` is called (they are also released when garbage collected), so release
 * them when finished. Pass arguments as the Rust types describe: `u64` values are
 * `bigint`, byte arrays are `Uint8Array`.
 */
import type { ClassName, Handle, Ref, Target } from "./protocol";
import type {
  ActivityEntry,
  ActivityMetadata,
  ActivityQuery,
  CredentialConstraintsCheckResult,
  CredentialRecord,
  Environment,
  GatewayRequestStatus,
  RecoveryData,
  RecoveryUpdateSignature,
  Region,
  RegistrationStatus,
} from "./types";

/** @internal The transport the proxies use to reach the worker. */
export interface Rpc {
  call(target: Target, args: unknown[]): Promise<unknown>;
  release(handle: Handle): void;
}

const nowSeconds = () => BigInt(Math.floor(Date.now() / 1000));

const finalizer = new FinalizationRegistry<{ rpc: Rpc; handle: Handle }>(
  ({ rpc, handle }) => rpc.release(handle),
);

/** A Rust object owned by the worker. */
export abstract class RemoteObject {
  /** @internal */
  readonly rpc: Rpc;
  /** @internal */
  readonly handle: Handle;

  /** @internal Objects are created by the API, not by consumers. */
  constructor(rpc: Rpc, handle: Handle) {
    this.rpc = rpc;
    this.handle = handle;
    finalizer.register(this, { rpc, handle }, this);
  }

  /** Releases the Rust object. Using it afterwards rejects. */
  free(): void {
    finalizer.unregister(this);
    this.rpc.release(this.handle);
  }

  /** @internal */
  protected invoke<T>(method: string, ...args: unknown[]): Promise<T> {
    return this.rpc.call({ handle: this.handle, method }, args) as Promise<T>;
  }
}

/** An element of the scalar field used by the World ID proofs. */
export class FieldElement extends RemoteObject {
  toBytes() {
    return this.invoke<Uint8Array>("toBytes");
  }
  toHexString() {
    return this.invoke<string>("toHexString");
  }
}

/** A World ID credential issued to the holder. */
export class Credential extends RemoteObject {
  sub() {
    return this.invoke<FieldElement>("sub");
  }
  issuerSchemaId() {
    return this.invoke<bigint>("issuerSchemaId");
  }
  genesisIssuedAt() {
    return this.invoke<bigint>("genesisIssuedAt");
  }
  expiresAt() {
    return this.invoke<bigint>("expiresAt");
  }
  associatedDataCommitment() {
    return this.invoke<FieldElement>("associatedDataCommitment");
  }
  claims() {
    return this.invoke<FieldElement[]>("claims");
  }
  claimsHex() {
    return this.invoke<string[]>("claimsHex");
  }
  toBytes() {
    return this.invoke<Uint8Array>("toBytes");
  }
}

/** A proof request received from a relying party. */
export class ProofRequest extends RemoteObject {
  toJson() {
    return this.invoke<string>("toJson");
  }
  id() {
    return this.invoke<string>("id");
  }
  version() {
    return this.invoke<number>("version");
  }
}

/** The response to a {@link ProofRequest}. */
export class ProofResponse extends RemoteObject {
  toJson() {
    return this.invoke<string>("toJson");
  }
  id() {
    return this.invoke<string>("id");
  }
  version() {
    return this.invoke<number>("version");
  }
  error() {
    return this.invoke<string | undefined>("error");
  }
}

/** The 32-byte database key that encrypts the credential store. */
export class StorageKeys extends RemoteObject {}

/** The location of the credential store inside the browser's OPFS pool. */
export class StoragePaths extends RemoteObject {
  rootPathString() {
    return this.invoke<string>("rootPathString");
  }
  worldidDirPathString() {
    return this.invoke<string>("worldidDirPathString");
  }
  vaultDbPathString() {
    return this.invoke<string>("vaultDbPathString");
  }
  cacheDbPathString() {
    return this.invoke<string>("cacheDbPathString");
  }
  lockPathString() {
    return this.invoke<string>("lockPathString");
  }
  groth16DirPathString() {
    return this.invoke<string>("groth16DirPathString");
  }
  queryZkeyPathString() {
    return this.invoke<string>("queryZkeyPathString");
  }
  nullifierZkeyPathString() {
    return this.invoke<string>("nullifierZkeyPathString");
  }
  queryGraphPathString() {
    return this.invoke<string>("queryGraphPathString");
  }
  nullifierGraphPathString() {
    return this.invoke<string>("nullifierGraphPathString");
  }
}

/** Proving material compiled into the WASM module. */
export class EmbeddedZkArtifacts extends RemoteObject {}

/** The encrypted store of credentials and activity. `now` defaults to the current time. */
export class CredentialStore extends RemoteObject {
  storagePaths() {
    return this.invoke<StoragePaths>("storagePaths");
  }
  init(leafIndex: bigint, now = nowSeconds()) {
    return this.invoke<void>("init", leafIndex, now);
  }
  listCredentials(issuerSchemaId?: bigint, now = nowSeconds()) {
    return this.invoke<CredentialRecord[]>(
      "listCredentials",
      issuerSchemaId,
      now,
    );
  }
  fetchCredential(issuerSchemaId: bigint, now = nowSeconds()) {
    return this.invoke<Credential | undefined>(
      "fetchCredential",
      issuerSchemaId,
      now,
    );
  }
  deleteCredential(credentialId: bigint) {
    return this.invoke<void>("deleteCredential", credentialId);
  }
  storeCredential(
    credential: Credential,
    blindingFactor: FieldElement,
    expiresAt: bigint,
    associatedData?: Uint8Array,
    now = nowSeconds(),
  ) {
    return this.invoke<bigint>(
      "storeCredential",
      credential,
      blindingFactor,
      expiresAt,
      associatedData,
      now,
    );
  }
  dangerDeleteAllCredentials() {
    return this.invoke<bigint>("dangerDeleteAllCredentials");
  }
  recordActivity(entry: ActivityEntry, now = nowSeconds()) {
    return this.invoke<bigint>("recordActivity", entry, now);
  }
  listActivities(query: ActivityQuery, limit: number, offset: number) {
    return this.invoke<ActivityEntry[]>("listActivities", query, limit, offset);
  }
  activityMetadata() {
    return this.invoke<ActivityMetadata>("activityMetadata");
  }
  clearActivities() {
    return this.invoke<bigint>("clearActivities");
  }
  destroyStorage() {
    return this.invoke<void>("destroyStorage");
  }
}

/** The main component with which users interact with the World ID Protocol. */
export class Authenticator extends RemoteObject {
  initStorage(now = nowSeconds()) {
    return this.invoke<void>("initStorage", now);
  }
  destroyStorage() {
    return this.invoke<void>("destroyStorage");
  }
  /** 0x-prefixed, zero-padded 256-bit hex string. */
  packedAccountData() {
    return this.invoke<string>("packedAccountData");
  }
  leafIndex() {
    return this.invoke<bigint>("leafIndex");
  }
  onchainAddress() {
    return this.invoke<string>("onchainAddress");
  }
  /** 0x-prefixed, zero-padded 256-bit hex string. */
  getPackedAccountDataRemote() {
    return this.invoke<string>("getPackedAccountDataRemote");
  }
  generateCredentialBlindingFactorRemote(issuerSchemaId: bigint) {
    return this.invoke<FieldElement>(
      "generateCredentialBlindingFactorRemote",
      issuerSchemaId,
    );
  }
  computeCredentialSub(blindingFactor: FieldElement) {
    return this.invoke<FieldElement>("computeCredentialSub", blindingFactor);
  }
  dangerSignChallenge(challenge: Uint8Array) {
    return this.invoke<Uint8Array>("dangerSignChallenge", challenge);
  }
  dangerSignInitiateRecoveryAgentUpdate(newRecoveryAgent: string) {
    return this.invoke<RecoveryUpdateSignature>(
      "dangerSignInitiateRecoveryAgentUpdate",
      newRecoveryAgent,
    );
  }
  /** Resolves with the gateway request ID. */
  updateRecoveryAgent(newRecoveryAgent: string) {
    return this.invoke<string>("updateRecoveryAgent", newRecoveryAgent);
  }
  /** Resolves with the gateway request ID. */
  revertRecoveryAgentUpdate() {
    return this.invoke<string>("revertRecoveryAgentUpdate");
  }
  /** Resolves with the gateway request ID. */
  insertAuthenticator(
    newAuthenticatorPubkey: string,
    newAuthenticatorAddress: string,
  ) {
    return this.invoke<string>(
      "insertAuthenticator",
      newAuthenticatorPubkey,
      newAuthenticatorAddress,
    );
  }
  hasAuthenticatorPubkey(authenticatorPubkey: string) {
    return this.invoke<boolean>("hasAuthenticatorPubkey", authenticatorPubkey);
  }
  /** Empty key set slots are `undefined`. */
  getAuthenticatorPubkeys() {
    return this.invoke<(string | undefined)[]>("getAuthenticatorPubkeys");
  }
  /** Resolves with the gateway request ID. */
  removeAuthenticator(
    authenticatorAddress: string,
    pubkeyId: number,
    expectedAuthenticatorPubkey: string,
  ) {
    return this.invoke<string>(
      "removeAuthenticator",
      authenticatorAddress,
      pubkeyId,
      expectedAuthenticatorPubkey,
    );
  }
  pollStatus(requestId: string) {
    return this.invoke<GatewayRequestStatus>("pollStatus", requestId);
  }
  generateProof(proofRequest: ProofRequest, now = nowSeconds()) {
    return this.invoke<ProofResponse>("generateProof", proofRequest, now);
  }
}

/** A World ID registration that has been submitted but not yet finalized. */
export class InitializingAuthenticator extends RemoteObject {
  pollStatus() {
    return this.invoke<RegistrationStatus>("pollStatus");
  }
}

/** @internal Constructors by class name, used to revive objects returned by the worker. */
export const REMOTE_CLASSES: Record<
  ClassName,
  new (rpc: Rpc, handle: Handle) => RemoteObject
> = {
  Authenticator,
  InitializingAuthenticator,
  CredentialStore,
  StorageKeys,
  StoragePaths,
  EmbeddedZkArtifacts,
  FieldElement,
  Credential,
  ProofRequest,
  ProofResponse,
};

/** Replaces remote objects with handles the worker can resolve. */
export function encode(value: unknown): unknown {
  if (value instanceof RemoteObject) {
    return { $ref: value.handle };
  }
  if (Array.isArray(value)) return value.map(encode);
  return value;
}

/** Revives refs returned by the worker into remote objects. */
export function decode(rpc: Rpc, value: unknown): unknown {
  if (Array.isArray(value)) return value.map((item) => decode(rpc, item));
  if (typeof value === "object" && value !== null && "$ref" in value) {
    const ref = value as Ref;
    return new REMOTE_CLASSES[ref.class](rpc, ref.$ref);
  }
  return value;
}

// ---------------------------------------------------------------------------
// Static constructors and the entry point, reached through `WalletKit`.
// ---------------------------------------------------------------------------

export interface FieldElementStatic {
  fromBytes(bytes: Uint8Array): Promise<FieldElement>;
  fromU64(value: bigint): Promise<FieldElement>;
  tryFromHexString(hexString: string): Promise<FieldElement>;
}

export interface CredentialStatic {
  fromBytes(bytes: Uint8Array): Promise<Credential>;
}

export interface ProofRequestStatic {
  fromJson(json: string): Promise<ProofRequest>;
}

export interface StorageKeysStatic {
  /** Wraps the 32-byte database key. Supply the same key to reopen the store. */
  fromBytes(databaseKey: Uint8Array): Promise<StorageKeys>;
}

export interface StoragePathsStatic {
  /** Derives every storage path from `root`, for example `/walletkit/<account>`. */
  fromRoot(root: string): Promise<StoragePaths>;
}

export interface EmbeddedZkArtifactsStatic {
  "new"(): Promise<EmbeddedZkArtifacts>;
}

export interface CredentialStoreStatic {
  /** Opens (or creates) the encrypted store at `paths`. */
  "new"(paths: StoragePaths, keys: StorageKeys): Promise<CredentialStore>;
}

export interface AuthenticatorStatic {
  /** Opens the authenticator for a registered `seed` using the environment defaults. */
  initWithDefaults(
    seed: Uint8Array,
    rpcUrl: string | undefined,
    environment: Environment,
    region: Region | undefined,
    artifacts: EmbeddedZkArtifacts,
    store: CredentialStore,
  ): Promise<Authenticator>;
  /** Like `initWithDefaults`, routing gateway traffic through OHTTP. */
  initWithOhttpDefaults(
    seed: Uint8Array,
    rpcUrl: string | undefined,
    environment: Environment,
    region: Region | undefined,
    artifacts: EmbeddedZkArtifacts,
    store: CredentialStore,
  ): Promise<Authenticator>;
  /** Opens the authenticator with an explicit JSON `config`. */
  init(
    seed: Uint8Array,
    config: string,
    artifacts: EmbeddedZkArtifacts,
    store: CredentialStore,
  ): Promise<Authenticator>;
}

export interface InitializingAuthenticatorStatic {
  /** Submits a registration for `seed` using the environment defaults. */
  registerWithDefaults(
    seed: Uint8Array,
    rpcUrl: string | undefined,
    environment: Environment,
    region: Region | undefined,
    recoveryAddress: string | undefined,
  ): Promise<InitializingAuthenticator>;
  /** Like `registerWithDefaults`, routing gateway traffic through OHTTP. */
  registerWithOhttpDefaults(
    seed: Uint8Array,
    rpcUrl: string | undefined,
    environment: Environment,
    region: Region | undefined,
    recoveryAddress: string | undefined,
  ): Promise<InitializingAuthenticator>;
  /** Submits a registration with an explicit JSON `config`. */
  register(
    seed: Uint8Array,
    config: string,
    recoveryAddress: string | undefined,
  ): Promise<InitializingAuthenticator>;
}

/** The API of one running worker. */
export interface WalletKit {
  readonly Authenticator: AuthenticatorStatic;
  readonly InitializingAuthenticator: InitializingAuthenticatorStatic;
  readonly CredentialStore: CredentialStoreStatic;
  readonly StorageKeys: StorageKeysStatic;
  readonly StoragePaths: StoragePathsStatic;
  readonly EmbeddedZkArtifacts: EmbeddedZkArtifactsStatic;
  readonly FieldElement: FieldElementStatic;
  readonly Credential: CredentialStatic;
  readonly ProofRequest: ProofRequestStatic;

  recoveryDataFromSeed(seed: Uint8Array): Promise<RecoveryData>;
  validateAuthenticatorPubkey(authenticatorPubkey: string): Promise<string>;
  checkCredentialsAgainstProofRequest(
    request: ProofRequest,
    store: CredentialStore,
    now?: bigint,
  ): Promise<CredentialConstraintsCheckResult>;
  pohRecoveryAgentAddress(environment: Environment): Promise<string>;
  worldIdVerifierAddress(environment: Environment): Promise<string>;

  /** Releases every Rust object, then terminates the worker. */
  close(): Promise<void>;
  /** Immediately stops the worker and rejects pending calls. */
  terminate(): void;
}

/** @internal Builds the `WalletKit` API on top of a transport. */
export function createApi(
  rpc: Rpc,
  lifecycle: Pick<WalletKit, "close" | "terminate">,
): WalletKit {
  const call = (target: Target, ...args: unknown[]) => rpc.call(target, args);
  const statics = <T>(className: ClassName, names: readonly (keyof T)[]): T =>
    Object.fromEntries(
      names.map((name) => [
        name,
        (...args: unknown[]) =>
          call({ class: className, static: name as string }, ...args),
      ]),
    ) as T;
  const construct = (className: ClassName) => ({
    new: (...args: unknown[]) =>
      call({ class: className, construct: true }, ...args),
  });
  const fn =
    <A extends unknown[], R>(
      name: Extract<Target, { function: string }>["function"],
    ) =>
    (...args: A) =>
      call({ function: name }, ...args) as Promise<R>;

  return {
    Authenticator: statics<AuthenticatorStatic>("Authenticator", [
      "initWithDefaults",
      "initWithOhttpDefaults",
      "init",
    ]),
    InitializingAuthenticator: statics<InitializingAuthenticatorStatic>(
      "InitializingAuthenticator",
      ["registerWithDefaults", "registerWithOhttpDefaults", "register"],
    ),
    CredentialStore: construct("CredentialStore") as CredentialStoreStatic,
    StorageKeys: statics<StorageKeysStatic>("StorageKeys", ["fromBytes"]),
    StoragePaths: statics<StoragePathsStatic>("StoragePaths", ["fromRoot"]),
    EmbeddedZkArtifacts: construct(
      "EmbeddedZkArtifacts",
    ) as EmbeddedZkArtifactsStatic,
    FieldElement: statics<FieldElementStatic>("FieldElement", [
      "fromBytes",
      "fromU64",
      "tryFromHexString",
    ]),
    Credential: statics<CredentialStatic>("Credential", ["fromBytes"]),
    ProofRequest: statics<ProofRequestStatic>("ProofRequest", ["fromJson"]),

    recoveryDataFromSeed: fn("recoveryDataFromSeed"),
    validateAuthenticatorPubkey: fn("validateAuthenticatorPubkey"),
    checkCredentialsAgainstProofRequest: (request, store, now = nowSeconds()) =>
      call(
        { function: "checkCredentialsAgainstProofRequest" },
        request,
        store,
        now,
      ) as Promise<CredentialConstraintsCheckResult>,
    pohRecoveryAgentAddress: fn("pohRecoveryAgentAddress"),
    worldIdVerifierAddress: fn("worldIdVerifierAddress"),

    close: lifecycle.close,
    terminate: lifecycle.terminate,
  };
}
