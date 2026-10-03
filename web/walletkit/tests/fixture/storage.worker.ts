// Test the Rust storage directly, independently of network registration.
// Uses the module built with the `test-hooks` feature.
import init, { WalletKit } from "../generated/walletkit.js";
self.onmessage = async ({ data }) => {
  try {
    await init({ module_or_path: new URL(data.wasmUrl) });
    const wallet = await WalletKit.open(
      "test-account",
      new Uint8Array(32).fill(data.secret),
      "staging",
      "eu",
      undefined,
    );
    try {
      wallet.testInitStorage(42n, 1000n);
      self.postMessage({ result: "initialized" });
    } finally {
      wallet.free();
    }
  } catch (error) {
    const e = error as Error & { detail?: string };
    self.postMessage({ error: `${e.name}: ${e.message} (${e.detail})` });
  }
};
