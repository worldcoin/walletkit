// Optimize the generated module before it is included in the npm package.
// Binaryen is supplied by the repository's `nix develop .#wasm` shell.
import { execFileSync } from "node:child_process";
import { renameSync } from "node:fs";
import { fileURLToPath } from "node:url";

const wasm = fileURLToPath(
  new URL("../src/generated/walletkit.wasm", import.meta.url),
);
const optimized = `${wasm}.optimized`;

execFileSync("wasm-opt", [wasm, "-Oz", "--converge", "-o", optimized], {
  stdio: "inherit",
});
renameSync(optimized, wasm);
