import { copyFileSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";

const source = new URL("../src/generated/", import.meta.url);
const output = new URL("../dist/generated/", import.meta.url);
mkdirSync(output, { recursive: true });
copyFileSync(
  new URL("walletkit.wasm", source),
  new URL("walletkit.wasm", output),
);

// The published typings derive the API from the generated declarations, so ship
// them too. Drop `[Symbol.dispose]`: the page frees objects with `free()`, and the
// symbol would otherwise require consumers to compile against `esnext.disposable`.
const declarations = readFileSync(new URL("walletkit.d.ts", source), "utf8");
writeFileSync(
  new URL("walletkit.d.ts", output),
  declarations.replace(/^\s*\[Symbol\.dispose\]\(\): void;\n/gm, ""),
);
