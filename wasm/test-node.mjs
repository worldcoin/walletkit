#!/usr/bin/env node
/**
 * Minimal smoke test for the WalletKit WASM bindings in a Node (ESM) runtime.
 *
 * Usage:
 *   node walletkit/wasm/test-node.mjs
 *
 * Ensure `wasm-pack` artifacts exist in `walletkit/wasm/pkg` first.
 */

import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const pkgDir = join(__dirname, "pkg");

const mod = await import(join(pkgDir, "walletkit_wasm.js"));
const { Authenticator, Environment } = mod;
console.log("✓ WASM module loaded\n");

console.log("Environment constants:");
console.log("  staging:", Environment.Staging().toString());
console.log("  production:", Environment.Production().toString());
console.log("");

const seed = new Uint8Array(32);

console.log("Invoking initWithDefaults (expected to fail without a real RPC/Gateway)...");
try {
  await Authenticator.initWithDefaults(
    seed,
    "https://example.invalid.rpc",
    Environment.Staging(),
  );
  console.log("Unexpected success; provide a valid RPC endpoint to exercise getters.");
} catch (error) {
  console.log("Received error (as string):", error.toString());
  console.log("✓ Error surfaced correctly\n");
}

console.log("You can now provide valid configuration details to fully exercise getters:");
console.log("  - accountId(): bigint");
console.log("  - onchainAddress(): string");
console.log("  - getPackedAccountIndexRemote(): Promise<bigint>");

