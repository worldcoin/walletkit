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

function destroy(value: unknown): void {
  (value as { uniffiDestroy(): void } | undefined)?.uniffiDestroy();
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

async function perform(request: Request): Promise<unknown> {
  switch (request.method) {
    case "initialize": {
      if (options) throw new Error("WalletKit is already initialized");
      const [input] = request.args;
      try {
        await bindings.uniffiInitAsync(new URL(input.wasmUrl));
        await bindings.initializePersistentStorage();
        const keyBytes = bytes(input.databaseKey);
        let keys: bindings.StorageKeysLike | undefined;
        let paths: bindings.StoragePathsLike | undefined;
        try {
          keys = bindings.StorageKeys.fromBytes(keyBytes);
          paths = bindings.StoragePaths.fromRoot(
            `/walletkit/${input.storageId}`,
          );
          store = new bindings.CredentialStore(paths, keys);
          options = input;
        } finally {
          new Uint8Array(keyBytes).fill(0);
          destroy(paths);
          destroy(keys);
        }
      } finally {
        input.databaseKey.fill(0);
      }
      return;
    }
    case "recoveryDataFromSeed": {
      const [seed] = request.args;
      try {
        return bindings.recoveryDataFromSeed(bytes(seed));
      } finally {
        seed.fill(0);
      }
    }
    case "register": {
      if (registration) throw new Error("Registration already started");
      const [seed] = request.args;
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
      return;
    }
    case "pollRegistration": {
      if (!registration) throw new Error("Start registration first");
      const status = await registration.pollStatus();
      const variants = bindings.RegistrationStatus;
      if (variants.Failed.instanceOf(status))
        return {
          state: "failed",
          ...status.inner,
        } satisfies RegistrationStatus;
      if (variants.Finalized.instanceOf(status)) return { state: "finalized" };
      if (variants.Submitted.instanceOf(status)) return { state: "submitted" };
      if (variants.Batching.instanceOf(status)) return { state: "batching" };
      return { state: "queued" };
    }
    case "initializeAuthenticator": {
      if (authenticator)
        throw new Error("Authenticator is already initialized");
      if (!store) throw new Error("WalletKit is not initialized");
      const [seed, now] = request.args;
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
      return;
    }
    case "prepareCredential": {
      const a = currentAuthenticator();
      const factor = await a.generateCredentialBlindingFactorRemote(
        request.args[0],
      );
      let sub: bindings.FieldElementLike | undefined;
      try {
        sub = a.computeCredentialSub(factor);
        return { blindingFactor: factor.toHexString(), sub: sub.toHexString() };
      } finally {
        destroy(sub);
        destroy(factor);
      }
    }
    case "storeCredential": {
      currentAuthenticator();
      const [serialized, factor, now] = request.args;
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
    case "generateProof": {
      const [json, now] = request.args;
      const proofRequest = bindings.ProofRequest.fromJson(json);
      let response:
        | Awaited<ReturnType<bindings.AuthenticatorLike["generateProof"]>>
        | undefined;
      try {
        response = await currentAuthenticator().generateProof(
          proofRequest,
          now,
        );
        return response.toJson();
      } finally {
        destroy(response);
        destroy(proofRequest);
      }
    }
    case "close": {
      // The client terminates this worker after the reply, releasing the OPFS pool.
      destroy(authenticator);
      destroy(registration);
      destroy(store);
      authenticator = undefined;
      registration = undefined;
      store = undefined;
      options = undefined;
      return;
    }
  }
}

// Serialize complete operations, including their awaits, so state cannot race.
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
