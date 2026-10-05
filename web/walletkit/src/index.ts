import { createApi, decode, encode } from "./remote";
import type { Rpc, WalletKit } from "./remote";
import type { Handle, Request, Response, Target } from "./protocol";

export type {
  ActivityQuery,
  Authenticator,
  Credential,
  CredentialStore,
  EmbeddedZkArtifacts,
  FieldElement,
  InitializingAuthenticator,
  ProofRequest,
  ProofResponse,
  RemoteClass,
  RemoteObject,
  StorageKeys,
  StoragePaths,
  WalletKit,
} from "./remote";
// Records are plain data and need no proxy.
export type {
  ActivityEntry,
  ActivityFailureReason,
  ActivityMetadata,
  ActivityOutcome,
  CredentialConstraintsCheckItem,
  CredentialConstraintsCheckResult,
  CredentialRecord,
  Environment,
  GatewayRequestStatus,
  RecoveryData,
  RecoveryUpdateSignature,
  Region,
  RegistrationStatus,
} from "./generated/walletkit.js";

export interface InitializeOptions {
  workerUrl?: string | URL;
  wasmUrl?: string | URL;
  /** Abort initialization and release the worker (for example on unmount). */
  signal?: AbortSignal;
}

/** How long `close()` waits for the worker before terminating it. */
const CLOSE_TIMEOUT_MS = 5000;

type Distribute<T> = T extends unknown ? Omit<T, "id"> : never;
type Message = Distribute<Request>;

class WorkerClient implements Rpc {
  private nextId = 0;
  private pending = new Map<
    number,
    { resolve(value: unknown): void; reject(reason: unknown): void }
  >();
  private stopped = false;
  /** Why the client stopped; any value, since an `AbortSignal` reason can be one. */
  private stopReason: unknown;
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
    if (this.stopped) return Promise.reject(this.stopReason);
    if (this.closing && message.op !== "close")
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

  /**
   * Releases every Rust object, then terminates the worker. The worker handles
   * requests in order, so a call that never settles would block the reply: after
   * {@link CLOSE_TIMEOUT_MS} the worker is terminated and the promise rejects.
   */
  close = (): Promise<void> => {
    if (this.stopped) return Promise.resolve();
    return (this.closing ??= this.closeWithDeadline());
  };

  /** Immediately stops the worker and rejects pending calls. */
  terminate = (): void => {
    this.abort(new Error("WalletKit was terminated"));
  };

  /** Stops the worker and rejects pending calls with `reason`, whatever it is. */
  abort(reason: unknown): void {
    this.stop(reason);
  }

  private async closeWithDeadline(): Promise<void> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const deadline = new Promise<never>((_, reject) => {
      timer = setTimeout(
        () =>
          reject(
            new Error(
              `WalletKit did not close within ${CLOSE_TIMEOUT_MS} ms; the worker was terminated`,
            ),
          ),
        CLOSE_TIMEOUT_MS,
      );
    });
    try {
      await Promise.race([this.send({ op: "close" }), deadline]);
    } finally {
      clearTimeout(timer);
      this.stop(new Error("WalletKit is closed"));
    }
  }

  private handleResponse(response: Response) {
    const pending = this.pending.get(response.id);
    if (!pending) return;
    this.pending.delete(response.id);
    if (response.ok) pending.resolve(response.result);
    else {
      const { name, message } = response.error;
      const error =
        name === "TypeError" ? new TypeError(message) : new Error(message);
      error.name = name;
      if (response.error.code)
        Object.assign(error, { code: response.error.code });
      pending.reject(error);
    }
  }

  private stop(reason: unknown) {
    if (!this.stopped) {
      this.stopped = true;
      this.stopReason = reason;
    }
    this.worker.terminate();
    for (const pending of this.pending.values()) pending.reject(reason);
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
  // Reject with the signal's own reason, like `signal.throwIfAborted()` does.
  const abort = () => client.abort(options.signal?.reason);

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
