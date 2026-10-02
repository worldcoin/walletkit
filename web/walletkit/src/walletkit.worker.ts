import * as bindings from "./generated";
import type {
  Request,
  Response,
  WorkerOptions,
  RegistrationStatus,
} from "./protocol";

const scope = globalThis as unknown as {
  onmessage: ((event: MessageEvent<Request>) => void) | null;
  postMessage(message: Response): void;
};

let options: WorkerOptions | undefined;
let registration: bindings.InitializingAuthenticatorLike | undefined;
let authenticator: bindings.AuthenticatorLike | undefined;
let store: bindings.CredentialStoreLike | undefined;

// Run one complete request at a time so awaited operations cannot interleave
// and race the worker's shared state.
let queue = Promise.resolve();

scope.onmessage = ({ data }) => {
  queue = queue.then(async () => {
    try {
      scope.postMessage({ id: data.id, ok: true, result: await perform(data) });
    } catch (error) {
      scope.postMessage({
        id: data.id,
        ok: false,
        error: {
          name: error instanceof Error ? error.name : "Error",
          message:
            error instanceof Error
              ? error.message +
                ("inner" in error
                  ? `: ${JSON.stringify(error.inner, (_, value) => (typeof value === "bigint" ? value.toString() : value))}`
                  : "")
              : String(error),
        },
      });
    }
  });
};

async function perform(request: Request): Promise<unknown> {
  switch (request.method) {
    case "initialize":
      return initialize(...request.args);

    case "recoveryDataFromSeed":
      return recoveryDataFromSeed(...request.args);

    case "register":
      return register(...request.args);

    case "pollRegistration":
      return pollRegistration(...request.args);

    case "initializeAuthenticator":
      return initializeAuthenticator(...request.args);

    case "prepareCredential":
      return prepareCredential(...request.args);

    case "storeCredential":
      return storeCredential(...request.args);

    case "generateProof":
      return generateProof(...request.args);

    case "close":
      return close();
  }
}

async function initialize(input: WorkerOptions): Promise<void> {
  if (options) throw new Error("WalletKit is already initialized");

  try {
    await bindings.uniffiInitAsync(new URL(input.wasmUrl));
    await bindings.initializePersistentStorage();
    store = createCredentialStore(input);
    options = input;
  } finally {
    input.databaseKey.fill(0);
  }
}

function recoveryDataFromSeed(seed: Uint8Array) {
  try {
    return bindings.recoveryDataFromSeed(bytes(seed));
  } finally {
    seed.fill(0);
  }
}

async function register(seed: Uint8Array): Promise<void> {
  if (registration) throw new Error("Registration already started");

  const c = config();

  try {
    registration =
      await bindings.InitializingAuthenticator.registerWithDefaults(
        bytes(seed),
        c.rpcUrl,
        c.environment,
        c.region,
        undefined,
      );
  } finally {
    seed.fill(0);
  }
}

async function pollRegistration(): Promise<RegistrationStatus> {
  if (!registration) throw new Error("Start registration first");

  const status = await registration.pollStatus();
  const variants = bindings.RegistrationStatus;

  if (variants.Failed.instanceOf(status)) {
    return { state: "failed", ...status.inner };
  }
  if (variants.Finalized.instanceOf(status)) return { state: "finalized" };
  if (variants.Submitted.instanceOf(status)) return { state: "submitted" };
  if (variants.Batching.instanceOf(status)) return { state: "batching" };

  return { state: "queued" };
}

async function initializeAuthenticator(
  seed: Uint8Array,
  now: bigint,
): Promise<void> {
  if (authenticator) throw new Error("Authenticator is already initialized");
  if (!store) throw new Error("WalletKit is not initialized");

  const c = config();

  try {
    const artifacts = new bindings.EmbeddedZkArtifacts();
    const source = artifacts.asZkArtifactSource();

    try {
      const initialized = await bindings.Authenticator.initWithDefaults(
        bytes(seed),
        c.rpcUrl,
        c.environment,
        c.region,
        source,
        store,
      );

      try {
        initialized.initStorage(now);
        authenticator = initialized;
      } catch (error) {
        destroy(initialized);
        throw error;
      }
    } finally {
      destroy(source);
      destroy(artifacts);
    }
  } finally {
    seed.fill(0);
  }
}

async function prepareCredential(issuerSchemaId: bigint) {
  const a = currentAuthenticator();
  const factor = await a.generateCredentialBlindingFactorRemote(issuerSchemaId);
  let sub: bindings.FieldElementLike | undefined;

  try {
    sub = a.computeCredentialSub(factor);
    return { blindingFactor: factor.toHexString(), sub: sub.toHexString() };
  } finally {
    destroy(sub);
    destroy(factor);
  }
}

function storeCredential(serialized: Uint8Array, factor: string, now: bigint) {
  currentAuthenticator();

  const credential = bindings.Credential.fromBytes(bytes(serialized));
  let blindingFactor: bindings.FieldElementLike | undefined;

  try {
    blindingFactor = bindings.FieldElement.tryFromHexString(factor);
    const credentialId = store!.storeCredential(
      credential,
      blindingFactor,
      credential.expiresAt(),
      undefined,
      now,
    );

    return { credentialId, issuerSchemaId: credential.issuerSchemaId() };
  } finally {
    destroy(blindingFactor);
    destroy(credential);
  }
}

async function generateProof(json: string, now: bigint): Promise<string> {
  const proofRequest = bindings.ProofRequest.fromJson(json);
  let response:
    | Awaited<ReturnType<bindings.AuthenticatorLike["generateProof"]>>
    | undefined;

  try {
    response = await currentAuthenticator().generateProof(proofRequest, now);
    return response.toJson();
  } finally {
    destroy(response);
    destroy(proofRequest);
  }
}

function close(): void {
  // The client terminates this worker after the reply, releasing the OPFS pool.
  destroy(authenticator);
  destroy(registration);
  destroy(store);

  authenticator = undefined;
  registration = undefined;
  store = undefined;
  options = undefined;
}

function createCredentialStore(input: WorkerOptions) {
  const keyBytes = bytes(input.databaseKey);
  let keys: bindings.StorageKeysLike | undefined;
  let paths: bindings.StoragePathsLike | undefined;

  try {
    keys = bindings.StorageKeys.fromBytes(keyBytes);
    paths = bindings.StoragePaths.fromRoot(`/walletkit/${input.storageId}`);
    return new bindings.CredentialStore(paths, keys);
  } finally {
    new Uint8Array(keyBytes).fill(0);
    destroy(paths);
    destroy(keys);
  }
}

function config() {
  if (!options) throw new Error("WalletKit is not initialized");
  return {
    environment:
      options.environment === "staging"
        ? bindings.Environment.Staging
        : bindings.Environment.Production,
    region: {
      eu: bindings.Region.Eu,
      us: bindings.Region.Us,
      ap: bindings.Region.Ap,
    }[options.region],
    rpcUrl: options.rpcUrl,
  };
}

function currentAuthenticator() {
  if (!authenticator) throw new Error("Initialize the authenticator first");
  return authenticator;
}

function bytes(value: Uint8Array): ArrayBuffer {
  return new Uint8Array(value).buffer;
}

function destroy(value: unknown): void {
  (value as { uniffiDestroy(): void } | undefined)?.uniffiDestroy();
}
