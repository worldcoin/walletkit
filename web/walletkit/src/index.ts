import type {
  InitializeOptions,
  Method,
  Operations,
  RecoveryData,
  RegistrationStatus,
  Request,
  Response,
} from "./protocol";
export type {
  InitializeOptions,
  RecoveryData,
  RegistrationStatus,
} from "./protocol";

export interface WalletKit {
  recoveryDataFromSeed(seed: Uint8Array): Promise<RecoveryData>;
  register(seed: Uint8Array): Promise<void>;
  pollRegistration(): Promise<RegistrationStatus>;
  initializeAuthenticator(seed: Uint8Array, now?: bigint): Promise<void>;
  prepareCredential(
    issuerSchemaId: bigint,
  ): Promise<{ blindingFactor: string; sub: string }>;
  storeCredential(
    credential: Uint8Array,
    blindingFactor: string,
    now?: bigint,
  ): Promise<{ credentialId: bigint; issuerSchemaId: bigint }>;
  generateProof(requestJson: string, now?: bigint): Promise<string>;
  close(): Promise<void>;
  terminate(): void;
}

class WalletKitClient implements WalletKit {
  private nextId = 0;
  private pending = new Map<
    number,
    { resolve(value: unknown): void; reject(error: Error): void }
  >();
  private stopped = false;
  private closing?: Promise<void>;

  /** @internal Use initializeWalletKit(). */
  constructor(private readonly worker: Worker) {
    worker.onmessage = ({ data }: MessageEvent<Response>) =>
      this.handleResponse(data);
    worker.onerror = (event) =>
      this.stop(new Error(event.message || "WalletKit worker failed"));
    worker.onmessageerror = () =>
      this.stop(new Error("WalletKit worker message could not be decoded"));
  }

  /**
   * Sends a typed RPC request to the worker and returns a promise that is
   * settled by the response with the matching request ID. Rejects immediately
   * if the client is closing or closed.
   *
   * @internal Public methods provide the consumer-facing API.
   */
  call<M extends Method>(
    method: M,
    ...args: Operations[M]["args"]
  ): Promise<Operations[M]["result"]> {
    if (this.stopped || (this.closing && method !== "close"))
      return Promise.reject(new Error("WalletKit is closed"));
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      this.pending.set(id, {
        resolve: resolve as (value: unknown) => void,
        reject,
      });
      try {
        this.worker.postMessage({ id, method, args } as Request);
      } catch (error) {
        this.pending.delete(id);
        reject(error);
      }
    });
  }

  recoveryDataFromSeed(seed: Uint8Array) {
    return this.call("recoveryDataFromSeed", seed);
  }

  register(seed: Uint8Array) {
    return this.call("register", seed);
  }

  pollRegistration() {
    return this.call("pollRegistration");
  }

  initializeAuthenticator(
    seed: Uint8Array,
    now = BigInt(Math.floor(Date.now() / 1000)),
  ) {
    return this.call("initializeAuthenticator", seed, now);
  }

  prepareCredential(issuerSchemaId: bigint) {
    return this.call("prepareCredential", issuerSchemaId);
  }

  storeCredential(
    credential: Uint8Array,
    blindingFactor: string,
    now = BigInt(Math.floor(Date.now() / 1000)),
  ) {
    return this.call("storeCredential", credential, blindingFactor, now);
  }

  generateProof(
    requestJson: string,
    now = BigInt(Math.floor(Date.now() / 1000)),
  ) {
    return this.call("generateProof", requestJson, now);
  }

  /** Finishes queued work, releases Rust objects, then terminates the worker. */
  close(): Promise<void> {
    if (this.stopped) return Promise.resolve();
    return (this.closing ??= this.call("close").finally(() =>
      this.stop(new Error("WalletKit is closed")),
    ));
  }

  /** Immediately stops the worker and rejects pending calls. */
  terminate(): void {
    this.stop(new Error("WalletKit was terminated"));
  }

  private handleResponse(response: Response) {
    const pending = this.pending.get(response.id);
    if (!pending) return;
    this.pending.delete(response.id);
    if (response.ok) pending.resolve(response.result);
    else {
      const error = new Error(response.error.message);
      error.name = response.error.name;
      pending.reject(error);
    }
  }

  private stop(error: Error) {
    this.stopped = true;
    this.worker.terminate();
    for (const pending of this.pending.values()) pending.reject(error);
    this.pending.clear();
  }
}

/** Loads WASM and persistent OPFS storage in a package-managed dedicated worker. */
export async function initializeWalletKit(
  options: InitializeOptions,
): Promise<WalletKit> {
  if (options.databaseKey.byteLength !== 32) {
    throw new Error("Expected a 32-byte database key");
  }

  const storageId = options.storageId ?? "default";

  if (!/^[a-zA-Z0-9_-]{1,128}$/.test(storageId)) {
    throw new Error(
      "Invalid storageId: use 1–128 letters, digits, underscores or hyphens",
    );
  }

  options.signal?.throwIfAborted();

  // Keep this literal form: supported bundlers discover and emit the worker asset.
  const worker = options.workerUrl
    ? new Worker(new URL(options.workerUrl, globalThis.location.href), {
        type: "module",
      })
    : new Worker(new URL("./walletkit.worker.js", import.meta.url), {
        type: "module",
      });

  const client = new WalletKitClient(worker);
  const abort = () => client.terminate();

  options.signal?.addEventListener("abort", abort, { once: true });

  const databaseKey = new Uint8Array(options.databaseKey);

  try {
    const wasmUrl = options.wasmUrl
      ? new URL(options.wasmUrl, globalThis.location.href).href
      : new URL(
          new URL("./generated/walletkit.wasm", import.meta.url).href,
          globalThis.location.href,
        ).href;

    const workerOptions = {
      databaseKey,
      storageId,
      environment: options.environment ?? "production",
      region: options.region ?? "eu",
      rpcUrl: options.rpcUrl,
      wasmUrl,
    };

    await client.call("initialize", workerOptions);

    return client;
  } catch (error) {
    client.terminate();
    throw error;
  } finally {
    databaseKey.fill(0);
    options.signal?.removeEventListener("abort", abort);
  }
}
