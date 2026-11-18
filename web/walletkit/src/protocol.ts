/**
 * Messages between the page and the dedicated worker that owns the WASM module.
 *
 * Rust objects cannot cross `postMessage`, so the worker keeps them in a handle table
 * and the page holds opaque `Ref`s. Everything else is plain structured-clone data.
 */

import type {
  PoseGuardImages,
  PoseGuardPrompt,
} from "./generated/walletkit.js";

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
  | {
      op: "enrollPoseGuard";
      configJson: string;
      sub: string;
      custodyPublicKey: Uint8Array;
    }
  | { op: "release"; handle: Handle }
  | { op: "close" }
);

/** Continuations for a running enrollment, handled outside the RPC queue. */
export type PoseGuardReply = { id: number } & (
  | { op: "poseGuardImages"; images: PoseGuardImages }
  | { op: "cancelPoseGuard" }
);

export type Response = { id: number } & (
  | { ok: true; result: unknown }
  | {
      ok: false;
      /** `fatal`: the module trapped; the worker cannot serve further calls. */
      error: { name: string; message: string; code?: string; fatal?: boolean };
    }
  | { event: "poseGuardCaptureRequested"; prompt: PoseGuardPrompt }
);

/** @internal Clear transferred bytes after WASM has copied its arguments. */
export function clearBytes(value: unknown): void {
  if (value instanceof Uint8Array) value.fill(0);
  else if (Array.isArray(value)) value.forEach(clearBytes);
  else if (isRecord(value)) Object.values(value).forEach(clearBytes);
}

/** @internal Plain records can contain transferred image or key buffers. */
export function isRecord(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object") return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}
