/**
 * Messages between the page and the dedicated worker that owns the WASM module.
 *
 * Rust objects cannot cross `postMessage`, so the worker keeps them in a handle table
 * and the page holds opaque `Ref`s. Everything else is plain structured-clone data.
 */

export type Handle = number;

/** A Rust object owned by the worker. */
export interface Ref {
  $ref: Handle;
}

export type Target =
  | { function: string }
  | { class: string; static: string }
  | { handle: Handle; method: string };

export type Request = { id: number } & (
  | { op: "initialize"; wasmUrl: string }
  | { op: "call"; target: Target; args: unknown[] }
  | { op: "release"; handle: Handle }
  | { op: "close" }
);

export type Response = { id: number } & (
  | { ok: true; result: unknown }
  | {
      ok: false;
      /** `fatal`: the module trapped; the worker cannot serve further calls. */
      error: { name: string; message: string; code?: string; fatal?: boolean };
    }
);
