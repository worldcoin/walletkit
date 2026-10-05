import init, * as wasm from "./generated/walletkit.js";
import { CLASS_NAMES, FUNCTION_NAMES } from "./protocol";
import type {
  ClassName,
  Handle,
  Ref,
  Request,
  Response,
  Target,
} from "./protocol";

const scope = globalThis as unknown as {
  onmessage: ((event: MessageEvent<Request>) => void) | null;
  postMessage(message: Response): void;
};

type Exports = Record<string, any>;
const wasmExports = wasm as unknown as Exports;

/** Live Rust objects, addressed by the page through opaque handles. */
const objects = new Map<Handle, { free(): void }>();
let nextHandle = 0;

let initialized = false;
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
  switch (request.op) {
    case "initialize":
      return initialize(request.wasmUrl);
    case "call":
      return call(request.target, request.args);
    case "release":
      return release(request.handle);
    case "close":
      return close();
  }
}

async function initialize(wasmUrl: string): Promise<void> {
  if (initialized) throw new Error("WalletKit is already initialized");
  await init({ module_or_path: new URL(wasmUrl) });
  // Fails when another context owns the storage pool.
  await wasm.initializePersistentStorage();
  initialized = true;
}

async function call(target: Target, encodedArgs: unknown[]): Promise<unknown> {
  if (!initialized) throw new Error("WalletKit is not initialized");
  const args = encodedArgs.map(resolve);
  try {
    return reveal(await invoke(target, args));
  } finally {
    // The page sent copies; clear any secret bytes (seeds, keys) held here.
    for (const arg of args) if (arg instanceof Uint8Array) arg.fill(0);
  }
}

function invoke(target: Target, args: unknown[]): unknown {
  if ("function" in target) {
    if (!(FUNCTION_NAMES as readonly string[]).includes(target.function))
      throw new Error(`Unknown function: ${target.function}`);
    return wasmExports[target.function](...args);
  }
  if ("construct" in target) {
    return new (exportedClass(target.class))(...args);
  }
  if ("static" in target) {
    return callable(exportedClass(target.class), target.static)(...args);
  }
  const object = objects.get(target.handle);
  if (!object) throw new Error("WalletKit object was released");
  return callable(object, target.method).apply(object, args);
}

function exportedClass(name: ClassName): any {
  if (!(CLASS_NAMES as readonly string[]).includes(name))
    throw new Error(`Unknown class: ${name}`);
  return wasmExports[name];
}

/** Looks up a method that the Rust class itself exports. */
function callable(owner: any, name: string): (...args: unknown[]) => unknown {
  const home =
    typeof owner === "function" ? owner : Object.getPrototypeOf(owner);
  const method = Object.hasOwn(home, name) ? home[name] : undefined;
  if (typeof method !== "function" || name === "constructor" || name === "free")
    throw new Error(`Unknown method: ${name}`);
  return method;
}

/** Swaps handles from the page for the Rust objects they refer to. */
function resolve(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(resolve);
  if (typeof value === "object" && value !== null && "$ref" in value) {
    const object = objects.get((value as Ref).$ref);
    if (!object) throw new Error("WalletKit object was released");
    return object;
  }
  return value;
}

/** Keeps Rust objects in the worker and returns handles for the page. */
function reveal(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(reveal);
  for (const name of CLASS_NAMES) {
    if (value instanceof wasmExports[name]) {
      const handle = nextHandle++;
      objects.set(handle, value as { free(): void });
      return { $ref: handle, class: name } satisfies Ref;
    }
  }
  return value;
}

function release(handle: Handle): void {
  objects.get(handle)?.free();
  objects.delete(handle);
}

function close(): void {
  // The client terminates this worker after the reply, releasing the OPFS pool.
  for (const handle of [...objects.keys()]) release(handle);
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
