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
      /**
       * `fields`: variant fields to set on the page's error, such as `domain`.
       * `fatal`: the module trapped; the worker cannot serve further calls.
       */
      error: {
        name: string;
        message: string;
        code?: string;
        fields?: Record<string, unknown>;
        fatal?: boolean;
      };
    }
);

/** A plain object built by the Rust module or revived by `postMessage`. */
export function isRecord(value: unknown): value is Record<string, unknown> {
  return (
    typeof value === "object" &&
    value !== null &&
    Object.getPrototypeOf(value) === Object.prototype
  );
}

/** Copies `record`, applying `map` to each field. */
export function mapRecord(
  record: Record<string, unknown>,
  map: (value: unknown) => unknown,
): Record<string, unknown> {
  return Object.fromEntries(
    Object.entries(record).map(([key, value]) => [key, map(value)]),
  );
}
