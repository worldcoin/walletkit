import { defineConfig } from "vite";
export default defineConfig({
  root: new URL("./fixture", import.meta.url).pathname,
  worker: { format: "es" },
  build: { outDir: "../site", emptyOutDir: true },
});
