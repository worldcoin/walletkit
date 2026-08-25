// PROTOTYPE workaround: sqlite-wasm-rs requires wasm-bindgen >= 0.2.104,
// while ubrn 0.31.0-5 pins its post-processor to 0.2.100. Both sides must use
// the exact same schema, so align the installed generator with WalletKit.
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync } from "node:fs";

const root = new URL(
  "../node_modules/uniffi-bindgen-react-native/",
  import.meta.url,
);
const manifest = new URL("Cargo.toml", root);
const lockfile = new URL("Cargo.lock", root);
const oldDependency = 'wasm-bindgen-cli-support = "=0.2.100"';
const newDependency = 'wasm-bindgen-cli-support = "=0.2.126"';

const source = readFileSync(manifest, "utf8");
if (source.includes(oldDependency)) {
  writeFileSync(manifest, source.replace(oldDependency, newDependency));
}

if (
  existsSync(lockfile) &&
  /name = "wasm-bindgen-cli-support"\nversion = "0\.2\.100"/.test(
    readFileSync(lockfile, "utf8"),
  )
) {
  execFileSync(
    "cargo",
    [
      "update",
      "--manifest-path",
      manifest.pathname,
      "-p",
      "wasm-bindgen-cli-support@0.2.100",
      "--precise",
      "0.2.126",
    ],
    { stdio: "inherit" },
  );
}
