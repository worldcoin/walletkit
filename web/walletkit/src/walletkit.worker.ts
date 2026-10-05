import init, * as wasm from "./generated/walletkit.js";
import { API, CLASS_NAMES, FUNCTION_NAMES } from "./protocol";
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
const objects = new Map<
  Handle,
  { object: { free(): void }; className: ClassName }
>();
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
      // A crashed module can still be closed; the client then terminates the worker.
      if (crashed && data.op !== "close") throw crashed;
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
  let args: unknown[] = encodedArgs;
  try {
    args = encodedArgs.map(resolve);
    return reveal(await invoke(target, args));
  } finally {
    // The page sent copies; clear any secret bytes (seeds, keys) held here, even
    // when an argument failed to resolve.
    for (const arg of encodedArgs) if (arg instanceof Uint8Array) arg.fill(0);
  }
}

/** Calls only what the API registry lists; never wasm-bindgen internals. */
function invoke(target: Target, args: unknown[]): unknown {
  if ("function" in target) {
    if (!(FUNCTION_NAMES as readonly string[]).includes(target.function))
      throw new Error(`Unknown function: ${target.function}`);
    return wasmExports[target.function](...args);
  }
  if ("handle" in target) {
    const entry = objects.get(target.handle);
    if (!entry) throw new Error("WalletKit object was released");
    const methods: readonly string[] = API[entry.className].methods;
    if (!methods.includes(target.method))
      throw new Error(`Unknown method: ${entry.className}.${target.method}`);
    const object = entry.object as unknown as Record<
      string,
      (...args: unknown[]) => unknown
    >;
    return object[target.method](...args);
  }
  const spec = API[target.class] as
    | { construct?: true; statics: readonly string[] }
    | undefined;
  if (!spec || !Object.hasOwn(API, target.class))
    throw new Error(`Unknown class: ${target.class}`);
  const constructor = wasmExports[target.class];
  if ("construct" in target) {
    if (!spec.construct) throw new Error(`${target.class} has no constructor`);
    return new constructor(...args);
  }
  if (!spec.statics.includes(target.static))
    throw new Error(`Unknown function: ${target.class}.${target.static}`);
  return constructor[target.static](...args);
}

/** Swaps handles from the page for the Rust objects they refer to. */
function resolve(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(resolve);
  if (typeof value === "object" && value !== null && "$ref" in value) {
    const entry = objects.get((value as Ref).$ref);
    if (!entry) throw new Error("WalletKit object was released");
    return entry.object;
  }
  return value;
}

/** Keeps Rust objects in the worker and returns handles for the page. */
function reveal(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(reveal);
  for (const className of CLASS_NAMES) {
    if (value instanceof wasmExports[className]) {
      const handle = nextHandle++;
      objects.set(handle, {
        object: value as { free(): void },
        className,
      });
      return { $ref: handle, class: className } satisfies Ref;
    }
  }
  return value;
}

function release(handle: Handle): void {
  const entry = objects.get(handle);
  objects.delete(handle);
  entry?.object.free();
}

function close(): void {
  // The client terminates this worker after the reply, releasing the OPFS pool.
  // A crashed module cannot run destructors, so ignore their failures.
  for (const handle of [...objects.keys()]) {
    try {
      release(handle);
    } catch (error) {
      if (!crashed) throw error;
    }
  }
}

function serialize(error: unknown): {
  name: string;
  message: string;
  code?: string;
} {
  if (!(error instanceof Error))
    return { name: "Error", message: String(error) };
  const { detail, code } = error as { detail?: unknown; code?: unknown };
  return {
    name: error.name,
    message:
      typeof detail === "string"
        ? `${error.message} (${detail})`
        : error.message,
    ...(typeof code === "string" && { code }),
  };
}
