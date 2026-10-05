// Builds the `walletkit-web` crate for the browser and stages the wasm-bindgen
// glue plus the optimized module (`walletkit.wasm`) in the output directory.
// The pinned wasm-bindgen CLI and Binaryen come from `nix develop .#wasm`.
import { execFileSync } from "node:child_process";
import { readFileSync, renameSync, rmSync } from "node:fs";
import { join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

const { values } = parseArgs({
  options: {
    "out-dir": { type: "string", default: "src/generated" },
  },
});

const packageDir = fileURLToPath(new URL("..", import.meta.url));
const outDir = resolve(packageDir, values["out-dir"]);
if (
  outDir === resolve(packageDir) ||
  !outDir.startsWith(resolve(packageDir) + sep)
) {
  throw new Error(`--out-dir must be a subdirectory of ${packageDir}`);
}
const run = (command, args) =>
  execFileSync(command, args, { cwd: packageDir, stdio: "inherit" });

// The CLI must match the wasm-bindgen crate linked into the module exactly,
// otherwise it rejects the module's embedded descriptors.
const lockfile = readFileSync(
  new URL("../../../Cargo.lock", import.meta.url),
  "utf8",
);
const expected = lockfile.match(
  /\nname = "wasm-bindgen"\nversion = "([^"]+)"/,
)?.[1];
if (!expected) throw new Error("wasm-bindgen is missing from Cargo.lock");
const installed = execFileSync("wasm-bindgen", ["--version"], {
  encoding: "utf8",
})
  .trim()
  .split(" ")[1];
if (installed !== expected) {
  throw new Error(
    `wasm-bindgen CLI ${installed} does not match ${expected} from Cargo.lock. ` +
      `Run inside \`nix develop .#wasm\` or install it with ` +
      `\`cargo install wasm-bindgen-cli --version ${expected} --locked\`.`,
  );
}

run("cargo", [
  "build",
  "-p",
  "walletkit-web",
  "--release",
  "--locked",
  "--target",
  "wasm32-unknown-unknown",
]);

const { target_directory: targetDir } = JSON.parse(
  execFileSync("cargo", ["metadata", "--format-version", "1", "--no-deps"], {
    cwd: packageDir,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  }),
);

rmSync(outDir, { force: true, recursive: true });
run("wasm-bindgen", [
  join(targetDir, "wasm32-unknown-unknown/release/walletkit_web.wasm"),
  "--target",
  "web",
  "--omit-default-module-path",
  "--out-dir",
  outDir,
  "--out-name",
  "walletkit",
]);

const wasm = join(outDir, "walletkit.wasm");
run("wasm-opt", [
  join(outDir, "walletkit_bg.wasm"),
  "-Oz",
  "--converge",
  "-o",
  wasm,
]);
rmSync(join(outDir, "walletkit_bg.wasm"));
renameSync(
  join(outDir, "walletkit_bg.wasm.d.ts"),
  join(outDir, "walletkit.wasm.d.ts"),
);
