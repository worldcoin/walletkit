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
);

export type WorkerEvent = {
  id: number;
  event: "poseGuardCaptureRequested";
  prompt: PoseGuardPrompt;
};

export type WorkerMessage = Response | WorkerEvent;

/** @internal Clear transferred bytes after WASM has copied its arguments. */
export function clearBytes(value: unknown): void {
  const pending = [value];
  // Structured cloning preserves shared references and cycles.
  const visited = new WeakSet<object>();
  while (pending.length > 0) {
    const item = pending.pop();
    if (typeof item !== "object" || item === null || visited.has(item))
      continue;
    visited.add(item);

    if (item instanceof Uint8Array) {
      item.fill(0);
    } else if (Array.isArray(item)) {
      for (const child of item) pending.push(child);
    } else if (isRecord(item)) {
      for (const child of Object.values(item)) pending.push(child);
    }
  }
}

/** @internal Plain records can contain transferred image or key buffers. */
export function isRecord(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object") return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}
