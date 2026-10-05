import { createApi, decode, encode } from "./api";
import type { Rpc, WalletKit } from "./api";
import type { Handle, Request, Response, Target } from "./protocol";

export {
  Authenticator,
  Credential,
  CredentialStore,
  EmbeddedZkArtifacts,
  FieldElement,
  InitializingAuthenticator,
  ProofRequest,
  ProofResponse,
  RemoteObject,
  StorageKeys,
  StoragePaths,
} from "./api";
export type {
  AuthenticatorStatic,
  CredentialStatic,
  CredentialStoreStatic,
  EmbeddedZkArtifactsStatic,
  FieldElementStatic,
  InitializingAuthenticatorStatic,
  ProofRequestStatic,
  StorageKeysStatic,
  StoragePathsStatic,
  WalletKit,
} from "./api";
export type * from "./types";

export interface InitializeOptions {
  workerUrl?: string | URL;
  wasmUrl?: string | URL;
  /** Abort initialization and release the worker (for example on unmount). */
  signal?: AbortSignal;
}

type Distribute<T> = T extends unknown ? Omit<T, "id"> : never;
type Message = Distribute<Request>;

class WorkerClient implements Rpc {
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
   * Sends a request to the worker and returns a promise that is settled by the
   * response with the matching request ID. Rejects immediately if the client is
   * closing or closed.
   */
  send(message: Message): Promise<unknown> {
    if (this.stopped || (this.closing && message.op !== "close"))
      return Promise.reject(new Error("WalletKit is closed"));
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      try {
        this.worker.postMessage({ ...message, id } as Request);
      } catch (error) {
        this.pending.delete(id);
        reject(error);
      }
    });
  }

  async call(target: Target, args: unknown[]): Promise<unknown> {
    return decode(
      this,
      await this.send({ op: "call", target, args: args.map(encode) }),
    );
  }

  release(handle: Handle): void {
    // Best effort: a stopped worker has already dropped its objects.
    this.send({ op: "release", handle }).catch(() => {});
  }

  /** Releases every Rust object, then terminates the worker. */
  close = (): Promise<void> => {
    if (this.stopped) return Promise.resolve();
    return (this.closing ??= this.send({ op: "close" })
      .then(() => {})
      .finally(() => this.stop(new Error("WalletKit is closed"))));
  };

  /** Immediately stops the worker and rejects pending calls. */
  terminate = (): void => {
    this.stop(new Error("WalletKit was terminated"));
  };

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

/**
 * Loads WASM and persistent OPFS storage in a package-managed dedicated worker.
 *
 * Open the account's storage with `StorageKeys` and `StoragePaths` on the returned
 * API, as the Swift and Kotlin bindings do.
 */
export async function initializeWalletKit(
  options: InitializeOptions = {},
): Promise<WalletKit> {
  options.signal?.throwIfAborted();

  // Keep this literal form: supported bundlers discover and emit the worker asset.
  const worker = options.workerUrl
    ? new Worker(new URL(options.workerUrl, globalThis.location.href), {
        type: "module",
      })
    : new Worker(new URL("./walletkit.worker.js", import.meta.url), {
        type: "module",
      });

  const client = new WorkerClient(worker);
  const abort = () => client.terminate();

  options.signal?.addEventListener("abort", abort, { once: true });

  try {
    const wasmUrl = options.wasmUrl
      ? new URL(options.wasmUrl, globalThis.location.href).href
      : new URL(
          new URL("./generated/walletkit.wasm", import.meta.url).href,
          globalThis.location.href,
        ).href;

    await client.send({ op: "initialize", wasmUrl });

    return createApi(client, client);
  } catch (error) {
    client.terminate();
    throw error;
  } finally {
    options.signal?.removeEventListener("abort", abort);
  }
}
