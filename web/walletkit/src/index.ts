import * as generated from "./generated";

export type * from "./generated";

type GeneratedWalletKit = typeof generated;

/** WalletKit's generated domain interface without its raw runtime hooks. */
export type WalletKit = Omit<GeneratedWalletKit, "default" | "uniffiInitAsync">;

const wasm = new URL("./generated/walletkit.wasm", import.meta.url);

/**
 * Loads WalletKit's browser WASM module and returns its generated bindings.
 * Repeated calls share the generated runtime's initialization promise.
 */
export async function initializeWalletKit(): Promise<WalletKit> {
  await generated.uniffiInitAsync(wasm);
  return generated;
}
