// Optimize the generated module before it is copied into Next.js public assets.
// Binaryen is supplied by the repository's `nix develop .#wasm` shell.
import { execFileSync } from "node:child_process";
import { renameSync } from "node:fs";
import { fileURLToPath } from "node:url";

const wasm = fileURLToPath(
  new URL(
    "../src/generated/walletkit_web_authenticator_poc.wasm",
    import.meta.url,
  ),
);
const optimized = `${wasm}.optimized`;

execFileSync("wasm-opt", [wasm, "-Oz", "--converge", "-o", optimized], {
  stdio: "inherit",
});
renameSync(optimized, wasm);
