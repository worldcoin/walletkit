import init, * as wasm from "./generated/walletkit.js";
import type { Handle, Ref, Request, Response, Target } from "./protocol";

const scope = globalThis as unknown as {
  onmessage: ((event: MessageEvent<Request>) => void) | null;
  postMessage(message: Response): void;
};

type RustObject = { free(): void };
type RustClass = { prototype: RustObject } & Record<string, unknown>;

const wasmExports = wasm as unknown as Record<string, unknown>;
/** Exports the page must not call: module setup, run by `initialize`. */
const INTERNAL = new Set([
  "default",
  "initSync",
  "start",
  "initializePersistentStorage",
]);

const isClass = (value: unknown): value is RustClass =>
  typeof value === "function" &&
  typeof (value as unknown as Partial<RustClass>).prototype?.free ===
    "function";
const classes = Object.values(wasmExports).filter(isClass);

/**
 * Whether the page may call `name`. wasm-bindgen's own members (`__wrap`,
 * `__destroy_into_raw`, …) all start with `_`; `free` goes through `release`.
 */
const callable = (name: string) =>
  !name.startsWith("_") && name !== "free" && name !== "constructor";

/** Live Rust objects, addressed by the page through opaque handles. */
const objects = new Map<Handle, RustObject>();
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
      scope.postMessage({
        id: data.id,
        ok: false,
        error: { ...serialize(error), ...(crashed && { fatal: true }) },
      });
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
  await installPersistentStorage();
  initialized = true;
}

/**
 * Backoff before each retry of the OPFS pool install. A context that just closed
 * (a reload, a remount) releases its handles asynchronously, so its successor can
 * briefly see the pool as owned. About 3 s in total, then the error is reported.
 */
const POOL_RETRY_DELAYS_MS = [100, 200, 400, 800, 1600];

async function installPersistentStorage(): Promise<void> {
  for (let attempt = 0; ; attempt++) {
    try {
      return await wasm.initializePersistentStorage();
    } catch (error) {
      const delay = POOL_RETRY_DELAYS_MS[attempt];
      const poolBusy =
        (error as { code?: unknown }).code === "PersistentStorage";
      if (!poolBusy || delay === undefined) throw error;
      // Jitter so contexts racing for the pool do not retry in lockstep.
      await new Promise((resolve) =>
        setTimeout(resolve, delay * (0.5 + Math.random() / 2)),
      );
    }
  }
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

/** Calls only functions and methods the Rust module exports. */
function invoke(target: Target, args: unknown[]): unknown {
  if ("function" in target) {
    const fn = wasmExports[target.function];
    if (
      !Object.hasOwn(wasmExports, target.function) ||
      !callable(target.function) ||
      INTERNAL.has(target.function) ||
      typeof fn !== "function" ||
      isClass(fn)
    )
      throw new Error(`Unknown function: ${target.function}`);
    return fn(...args);
  }
  if ("class" in target) {
    const cls = Object.hasOwn(wasmExports, target.class)
      ? wasmExports[target.class]
      : undefined;
    if (!isClass(cls)) throw new Error(`Unknown class: ${target.class}`);
    return own(cls, target.static, `${target.class}.${target.static}`)(...args);
  }
  const object = objects.get(target.handle);
  if (!object) throw new Error("WalletKit object was released");
  const method = own(
    Object.getPrototypeOf(object),
    target.method,
    target.method,
  );
  return method.apply(object, args);
}

/** An own function property of `home` that the page may call. */
function own(
  home: Record<string, unknown>,
  name: string,
  label: string,
): (...args: unknown[]) => unknown {
  const value = Object.hasOwn(home, name) ? home[name] : undefined;
  if (!callable(name) || typeof value !== "function")
    throw new Error(`Unknown function: ${label}`);
  return value as (...args: unknown[]) => unknown;
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
  if (classes.some((cls) => value instanceof (cls as unknown as Function))) {
    const handle = nextHandle++;
    objects.set(handle, value as RustObject);
    return { $ref: handle } satisfies Ref;
  }
  return value;
}

function release(handle: Handle): void {
  const object = objects.get(handle);
  objects.delete(handle);
  object?.free();
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
