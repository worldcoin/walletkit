/**
 * The page-side API: a typed proxy over the worker that owns the WASM module.
 *
 * Classes, functions and records come straight from the generated wasm-bindgen
 * declarations, which mirror the Swift and Kotlin bindings, so there is no second
 * copy of the API to keep in sync. Rust objects stay in the worker; the page holds
 * proxies whose methods are asynchronous. Release them with `free()` (they are also
 * released when garbage collected).
 */
import type * as Wasm from "./generated/walletkit.js";
import type { Handle, Ref, Target } from "./protocol";

type Exports = typeof Wasm;
type RustObject = { free(): void };

/**
 * Exported Rust classes: every export whose instances can be freed. A plain
 * function's `prototype` is `any`, which must not count.
 */
type ClassName = {
  [K in keyof Exports]: Exports[K] extends { prototype: infer P }
    ? 0 extends 1 & P
      ? never
      : P extends RustObject
        ? K
        : never
    : never;
}[keyof Exports];

/** Exports only the worker itself uses. */
type Internal =
  | "default"
  | "initSync"
  | "start"
  | "initializePersistentStorage";

type FunctionName = {
  [K in keyof Exports]: K extends ClassName | Internal
    ? never
    : Exports[K] extends (...args: never[]) => unknown
      ? K
      : never;
}[keyof Exports];

/** A Rust object kept in the worker: each method returns a promise. */
export type RemoteObject<T> = {
  [K in keyof T as K extends "free" | symbol ? never : K]: RemoteFunction<T[K]>;
} & { free(): void };

/** The static functions of a Rust class, including `new` where it has one. */
export type RemoteClass<C> = {
  [K in keyof C as K extends "prototype" | symbol ? never : K]: RemoteFunction<
    C[K]
  >;
};

type RemoteFunction<F> = F extends (...args: infer A) => infer R
  ? (...args: { [I in keyof A]: Local<A[I]> }) => Promise<Remote<Awaited<R>>>
  : never;
/** Values returned by the worker: Rust objects become proxies. */
type Remote<T> = T extends RustObject
  ? RemoteObject<T>
  : T extends readonly (infer U)[]
    ? Remote<U>[]
    : T;
/** Arguments sent to the worker: Rust objects are passed as their proxies. */
type Local<T> = T extends RustObject ? RemoteObject<T> : T;

/** The API of one running worker. */
export type WalletKit = {
  readonly [K in ClassName]: RemoteClass<Exports[K]>;
} & {
  readonly [K in FunctionName]: RemoteFunction<Exports[K]>;
} & {
  /** Frees every Rust object, then terminates the worker. */
  close(): Promise<void>;
  /** Immediately stops the worker and rejects pending calls. */
  terminate(): void;
};

export type ActivityQuery = RemoteObject<Wasm.ActivityQuery>;
export type Authenticator = RemoteObject<Wasm.Authenticator>;
export type InitializingAuthenticator =
  RemoteObject<Wasm.InitializingAuthenticator>;
export type CredentialStore = RemoteObject<Wasm.CredentialStore>;
export type StorageKeys = RemoteObject<Wasm.StorageKeys>;
export type StoragePaths = RemoteObject<Wasm.StoragePaths>;
export type EmbeddedZkArtifacts = RemoteObject<Wasm.EmbeddedZkArtifacts>;
export type FieldElement = RemoteObject<Wasm.FieldElement>;
export type Credential = RemoteObject<Wasm.Credential>;
export type ProofRequest = RemoteObject<Wasm.ProofRequest>;
export type ProofResponse = RemoteObject<Wasm.ProofResponse>;

/** @internal The transport the proxies use to reach the worker. */
export interface Rpc {
  call(target: Target, args: unknown[]): Promise<unknown>;
  release(handle: Handle): void;
}

/** The worker object behind a proxy, and the client that owns it. */
interface Binding {
  rpc: Rpc;
  handle: Handle;
  released: boolean;
}

const bindings = new WeakMap<object, Binding>();
// Holds plain data, never a closure: a closure created next to the proxy would share
// its scope with the proxy and keep it reachable, so it would never be collected.
const finalizer = new FinalizationRegistry<Binding>((binding) =>
  release(binding),
);

function release(binding: Binding): void {
  if (binding.released) return;
  binding.released = true;
  binding.rpc.release(binding.handle);
}

/**
 * @internal Replaces proxies with the handles `rpc`'s worker can resolve. A proxy
 * from another (for example closed and reopened) client, or one already freed, is
 * rejected rather than sent: its handle could name an unrelated object there.
 *
 * Byte arrays are copied, and the copies' buffers are added to `transfer` so that
 * `postMessage` moves them to the worker (which clears them) instead of leaving a
 * second copy of a seed or key in the page heap. The caller's array is untouched.
 */
export function encode(
  rpc: Rpc,
  value: unknown,
  transfer: ArrayBuffer[],
): unknown {
  if (typeof value === "object" && value !== null) {
    const binding = bindings.get(value);
    if (binding !== undefined) {
      if (binding.rpc !== rpc) {
        throw new TypeError(
          "This WalletKit object belongs to a different WalletKit instance",
        );
      }
      if (binding.released) {
        throw new TypeError("This WalletKit object was freed");
      }
      return { $ref: binding.handle } satisfies Ref;
    }
  }
  if (Array.isArray(value)) {
    return value.map((item) => encode(rpc, item, transfer));
  }
  // Copying also sends only the viewed bytes, not a view's whole backing buffer.
  if (value instanceof Uint8Array) {
    const copy = value.slice();
    transfer.push(copy.buffer);
    return copy;
  }
  return value;
}

/** @internal Revives handles returned by the worker as proxies. */
export function decode(rpc: Rpc, value: unknown): unknown {
  if (Array.isArray(value)) return value.map((item) => decode(rpc, item));
  if (typeof value === "object" && value !== null && "$ref" in value) {
    return remoteObject({ rpc, handle: (value as Ref).$ref, released: false });
  }
  return value;
}

function remoteObject(binding: Binding): object {
  const { rpc, handle } = binding;
  const proxy: object = new Proxy(Object.create(null), {
    get(_, name) {
      if (name === "free") {
        return () => {
          finalizer.unregister(proxy);
          release(binding);
        };
      }
      // Not a thenable, and no symbol-keyed methods.
      if (typeof name !== "string" || name === "then") return undefined;
      return (...args: unknown[]) =>
        binding.released
          ? Promise.reject(new TypeError("This WalletKit object was freed"))
          : rpc.call({ handle, method: name }, args);
    },
  });
  bindings.set(proxy, binding);
  finalizer.register(proxy, binding, proxy);
  return proxy;
}

/** @internal Builds the `WalletKit` API on top of a transport. */
export function createApi(
  rpc: Rpc,
  lifecycle: Pick<WalletKit, "close" | "terminate">,
): WalletKit {
  const named = (call: (name: string) => unknown) =>
    new Proxy(Object.create(null), {
      get: (_, name) =>
        typeof name === "string" && name !== "then" ? call(name) : undefined,
    });
  const classes = new Map<string, unknown>();
  return named((name) => {
    if (name === "close") return lifecycle.close;
    if (name === "terminate") return lifecycle.terminate;
    // Classes are PascalCase and functions camelCase, as wasm-bindgen exports them.
    if (/^[A-Z]/.test(name)) {
      if (!classes.has(name)) {
        classes.set(
          name,
          named(
            (method) =>
              (...args: unknown[]) =>
                rpc.call({ class: name, static: method }, args),
          ),
        );
      }
      return classes.get(name);
    }
    return (...args: unknown[]) => rpc.call({ function: name }, args);
  }) as WalletKit;
}
