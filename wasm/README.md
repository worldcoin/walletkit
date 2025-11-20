# WalletKit WASM bindings

## Builds

Run the helper scripts from the workspace root (they forward additional arguments to `wasm-pack`):

```bash
./walletkit/wasm/scripts/build-web.sh      # Builds for browsers
./walletkit/wasm/scripts/build-node.sh     # Builds for Node.js (ESM + CJS)
```

Both scripts output artifacts to `walletkit/wasm/pkg/`.

## Usage sketch

```ts
import init, { Authenticator, Environment } from "./pkg/walletkit_wasm.js";
import { readFile } from "node:fs/promises";

const wasm = await readFile("./pkg/walletkit_wasm_bg.wasm");
await init(wasm);

const seed = new Uint8Array(32); // placeholder seed
const authenticator = await Authenticator.initWithDefaults(
  seed,
  "https://rpc.example.com",
  Environment.Staging()
);

console.log(authenticator.onchainAddress());
console.log(await authenticator.getPackedAccountIndexRemote()); // -> bigint
```
