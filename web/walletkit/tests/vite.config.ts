import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";

const poseGuardWasm = fileURLToPath(
  new URL("./fixture/poseguard-wasm.ts", import.meta.url),
);

export default defineConfig({
  root: new URL("./fixture", import.meta.url).pathname,
  worker: {
    format: "es",
    plugins: () => [
      {
        name: "poseguard-wasm-fixture",
        enforce: "pre",
        resolveId(source, importer) {
          if (
            source === "./generated/walletkit.js" &&
            importer?.endsWith("/src/walletkit.worker.ts")
          ) {
            return poseGuardWasm;
          }
        },
      },
    ],
  },
  build: { outDir: "../site", emptyOutDir: true },
});
