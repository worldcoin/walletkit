import { createApi, decode, encode } from "./remote";
import type { PoseGuardCapture, Rpc, WalletKit } from "./remote";
import { isRecord } from "./protocol";
import type {
  Handle,
  PoseGuardReply,
  Request,
  Response,
  Target,
  WorkerEvent,
  WorkerMessage,
} from "./protocol";
import type {
  PoseGuardImages,
  PoseGuardPrompt,
  SelfieEnrollmentResult,
} from "./generated/walletkit.js";

export type {
  ActivityQuery,
  Authenticator,
  Credential,
  CredentialStore,
  EmbeddedZkArtifacts,
  FieldElement,
  InitializingAuthenticator,
  PoseGuardCapture,
  PoseGuardOptions,
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
  LogLevel,
  RecoveryData,
  RecoveryUpdateSignature,
  Region,
  RegistrationStatus,
  FaceEmbedding,
  SelfieEmbeddingResult,
  PoseGuardImages,
  PoseGuardPrompt,
  PoseGuardTarget,
  SelfieCaptureFailure,
  SelfieEnrollmentBundle,
  SelfieEnrollmentResult,
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

interface PoseGuardAttempt {
  id: number;
  capture: PoseGuardCapture;
  controller: AbortController;
  prompted: boolean;
  cancellation?: { reason: unknown };
}

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
  private poseGuard?: PoseGuardAttempt;

  /** @internal Use initializeWalletKit(). */
  constructor(private readonly worker: Worker) {
    worker.onmessage = ({ data }: MessageEvent<WorkerMessage>) =>
      "event" in data ? this.handleEvent(data) : this.handleResponse(data);
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
  send(message: Message, transfer: Transferable[] = []): Promise<unknown> {
    return this.request({ ...message, id: this.nextId++ }, transfer);
  }

  private request(
    message: Request,
    transfer: Transferable[],
  ): Promise<unknown> {
    if (this.stopped) return Promise.reject(this.stopReason);
    if (this.closing && message.op !== "close")
      return Promise.reject(new Error("WalletKit is closed"));
    const { id } = message;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      try {
        this.worker.postMessage(message, transfer);
      } catch (error) {
        this.pending.delete(id);
        reject(error);
      }
    });
  }

  async call(target: Target, args: unknown[]): Promise<unknown> {
    const transfer: ArrayBuffer[] = [];
    let reply: Promise<unknown>;
    try {
      const encoded = args.map((arg) => encode(this, arg, transfer));
      reply = this.send({ op: "call", target, args: encoded }, transfer);
    } finally {
      // Transferred buffers are now detached and empty. Any copy left behind, because
      // encoding failed part-way or nothing was posted, is cleared here instead of
      // waiting for garbage collection.
      clearUnsent(transfer);
    }
    return decode(this, await reply);
  }

  enrollSelfieWithPoseGuard: WalletKit["enrollSelfieWithPoseGuard"] = async (
    configJson,
    sub,
    custodyPublicKey,
    capture,
    { signal } = {},
  ) => {
    signal?.throwIfAborted();
    if (this.poseGuard)
      throw new Error("PoseGuard enrollment already in progress");
    if (typeof configJson !== "string" || typeof sub !== "string")
      throw new TypeError("Expected configJson and sub strings");
    if (typeof capture !== "function")
      throw new TypeError("Expected a capture callback");
    if (
      !(custodyPublicKey instanceof Uint8Array) ||
      custodyPublicKey.length !== 32
    )
      throw new TypeError("custodyPublicKey must contain 32 bytes");

    const attempt: PoseGuardAttempt = {
      id: this.nextId++,
      capture,
      controller: new AbortController(),
      prompted: false,
    };
    this.poseGuard = attempt;
    const abort = () => this.cancelPoseGuard(attempt, signal?.reason);
    signal?.addEventListener("abort", abort, { once: true });

    try {
      const key = new Uint8Array(custodyPublicKey);
      let reply: Promise<unknown>;
      try {
        reply = this.request(
          {
            id: attempt.id,
            op: "enrollPoseGuard",
            configJson,
            sub,
            custodyPublicKey: key,
          },
          [key.buffer],
        );
      } finally {
        clearUnsent([key.buffer]);
      }
      const result = (await reply) as SelfieEnrollmentResult;
      if (attempt.cancellation) throw attempt.cancellation.reason;
      return result;
    } catch (error) {
      const reason = attempt.cancellation ? attempt.cancellation.reason : error;
      attempt.controller.abort(reason);
      throw reason;
    } finally {
      signal?.removeEventListener("abort", abort);
      this.poseGuard = undefined;
    }
  };

  private async sendPoseGuardImages(
    attempt: PoseGuardAttempt,
    prompt: PoseGuardPrompt,
  ) {
    const transfer: ArrayBuffer[] = [];
    try {
      const images = await attempt.capture(prompt, attempt.controller.signal);
      if (this.poseGuard !== attempt || attempt.controller.signal.aborted)
        return;
      const checked = validatePoseGuardImages(images);
      const copy = (image: Uint8Array) => {
        const owned = new Uint8Array(image);
        transfer.push(owned.buffer);
        return owned;
      };
      const [first, second, third] = checked.captures;
      this.worker.postMessage(
        {
          id: attempt.id,
          op: "poseGuardImages",
          images: {
            centralPng: copy(checked.centralPng),
            captures: [copy(first), copy(second), copy(third)],
          },
        } satisfies PoseGuardReply,
        transfer,
      );
    } catch (error) {
      this.cancelPoseGuard(attempt, error);
    } finally {
      clearUnsent(transfer);
    }
  }

  private cancelPoseGuard(attempt: PoseGuardAttempt, reason: unknown) {
    if (
      this.poseGuard !== attempt ||
      attempt.cancellation ||
      !this.pending.has(attempt.id)
    )
      return;
    attempt.cancellation = { reason };
    attempt.controller.abort(reason);
    try {
      this.worker.postMessage({
        id: attempt.id,
        op: "cancelPoseGuard",
      } satisfies PoseGuardReply);
    } catch (error) {
      this.stop(error);
    }
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
    return (this.closing ??= Promise.resolve().then(() =>
      this.closeWithDeadline(),
    ));
  };

  /** Whether this instance can no longer serve calls: closed, terminated or crashed. */
  isStopped = (): boolean => this.stopped;

  /** Immediately stops the worker and rejects pending calls. */
  terminate = (): void => {
    this.abort(new Error("WalletKit was terminated"));
  };

  /** Stops the worker and rejects pending calls with `reason`, whatever it is. */
  abort(reason: unknown): void {
    this.stop(reason);
  }

  private async closeWithDeadline(): Promise<void> {
    if (this.poseGuard)
      this.cancelPoseGuard(this.poseGuard, new Error("WalletKit is closing"));
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

  private handleEvent({ id, prompt }: WorkerEvent) {
    const attempt = this.poseGuard;
    if (attempt?.id !== id || attempt.cancellation || !this.pending.has(id))
      return;
    if (attempt.prompted) {
      this.cancelPoseGuard(
        attempt,
        new Error("Unexpected PoseGuard capture request"),
      );
      return;
    }
    attempt.prompted = true;
    void this.sendPoseGuardImages(attempt, prompt);
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
      // A trapped module cannot recover: stop, so every later call fails fast with
      // this error and `isStopped()` tells the app to reinitialize.
      if (response.error.fatal) this.stop(error);
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

function clearUnsent(transfer: ArrayBuffer[]) {
  for (const buffer of transfer) {
    // Buffers already transferred are detached.
    if (buffer.byteLength > 0) new Uint8Array(buffer).fill(0);
  }
}

function validatePoseGuardImages(value: unknown): PoseGuardImages {
  const { centralPng, captures } = isRecord(value) ? value : {};
  const validImage = (image: unknown): image is Uint8Array =>
    image instanceof Uint8Array &&
    image.length > 0 &&
    image.length <= 8 * 1024 * 1024;
  if (
    !validImage(centralPng) ||
    ![137, 80, 78, 71, 13, 10, 26, 10].every(
      (byte, index) => centralPng[index] === byte,
    )
  )
    throw new TypeError("centralPng must be a PNG no larger than 8 MiB");
  if (!Array.isArray(captures) || captures.length !== 3)
    throw new TypeError("Expected three PoseGuard capture images");
  const [first, second, third] = captures;
  if (!validImage(first) || !validImage(second) || !validImage(third))
    throw new TypeError(
      "Each PoseGuard capture must be a nonempty Uint8Array no larger than 8 MiB",
    );
  return { centralPng, captures: [first, second, third] };
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
