import { copyFileSync, mkdirSync } from "node:fs";

const output = new URL("../dist/generated/", import.meta.url);
mkdirSync(output, { recursive: true });
copyFileSync(
  new URL("../src/generated/walletkit.wasm", import.meta.url),
  new URL("walletkit.wasm", output),
);
