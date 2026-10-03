import init, {
  WalletKit,
  recoveryDataFromSeed,
} from "./generated/walletkit.js";
import type { Request, Response, WorkerOptions } from "./protocol";

const scope = globalThis as unknown as {
  onmessage: ((event: MessageEvent<Request>) => void) | null;
  postMessage(message: Response): void;
};

let wallet: WalletKit | undefined;
// A Rust panic traps the module and leaves its memory in an unknown state.
let crashed: Error | undefined;

// Run one complete request at a time so awaited operations cannot interleave
// and race the worker's shared state.
let queue = Promise.resolve();

scope.onmessage = ({ data }) => {
  queue = queue.then(async () => {
    try {
      if (crashed) throw crashed;
      scope.postMessage({ id: data.id, ok: true, result: await perform(data) });
    } catch (error) {
      if (error instanceof WebAssembly.RuntimeError) {
        crashed = new Error(
          `WalletKit crashed and must be reinitialized: ${error.message}`,
        );
      }
      scope.postMessage({ id: data.id, ok: false, error: serialize(error) });
    }
  });
};

async function perform(request: Request): Promise<unknown> {
  switch (request.method) {
    case "initialize":
      return initialize(...request.args);

    case "recoveryDataFromSeed":
      return consume(request.args[0], (seed) => {
        current();
        return recoveryDataFromSeed(seed);
      });

    case "register":
      return consume(request.args[0], (seed) => current().register(seed));

    case "pollRegistration":
      return current().pollRegistration();

    case "initializeAuthenticator": {
      const [seed, now] = request.args;
      return consume(seed, (seed) =>
        current().initializeAuthenticator(seed, now),
      );
    }

    case "prepareCredential":
      return current().prepareCredential(...request.args);

    case "storeCredential":
      return current().storeCredential(...request.args);

    case "generateProof":
      return current().generateProof(...request.args);

    case "close":
      return close();
  }
}

async function initialize(input: WorkerOptions): Promise<void> {
  if (wallet) throw new Error("WalletKit is already initialized");

  try {
    await init({ module_or_path: new URL(input.wasmUrl) });
    wallet = await WalletKit.open(
      input.storageId,
      input.databaseKey,
      input.environment,
      input.region,
      input.rpcUrl,
    );
  } finally {
    input.databaseKey.fill(0);
  }
}

function close(): void {
  // The client terminates this worker after the reply, releasing the OPFS pool.
  wallet?.close();
  wallet?.free();
  wallet = undefined;
}

function current(): WalletKit {
  if (!wallet) throw new Error("WalletKit is not initialized");
  return wallet;
}

/** Runs `operation` with secret bytes, then clears this worker's copy. */
async function consume<T>(
  secret: Uint8Array,
  operation: (secret: Uint8Array) => T | Promise<T>,
): Promise<T> {
  try {
    return await operation(secret);
  } finally {
    secret.fill(0);
  }
}

function serialize(error: unknown): { name: string; message: string } {
  if (!(error instanceof Error))
    return { name: "Error", message: String(error) };
  const detail = (error as { detail?: unknown }).detail;
  return {
    name: error.name,
    message:
      typeof detail === "string"
        ? `${error.message} (${detail})`
        : error.message,
  };
}
