import type { NextConfig } from "next";
import { fileURLToPath } from "node:url";

const nextConfig: NextConfig = {
  // The local file dependency is symlinked outside the example directory.
  // Published consumers resolve the package from their own node_modules and
  // do not need this development-only Turbopack root.
  turbopack: {
    root: fileURLToPath(new URL("../..", import.meta.url)),
  },
};

export default nextConfig;
