// PROTOTYPE workaround: ubrn 0.31.0-5 emits readonly player definitions that
// @ubjs/wasm 0.31.0-5 types as mutable, and omits a declaration for its
// generated wasm-bindgen glue module. Runtime shapes are compatible.
import { copyFileSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";

const generatedIndex = new URL("../src/generated/index.ts", import.meta.url);
const source = readFileSync(generatedIndex, "utf8");
if (!source.startsWith("// @ts-nocheck")) {
  writeFileSync(generatedIndex, `// @ts-nocheck\n${source}`);
}

const publicWasm = new URL("../public/wasm/", import.meta.url);
mkdirSync(publicWasm, { recursive: true });
copyFileSync(
  new URL(
    "../src/generated/walletkit_web_authenticator_poc.wasm",
    import.meta.url,
  ),
  new URL("walletkit_web_authenticator_poc.wasm", publicWasm),
);
