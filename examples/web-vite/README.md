# WalletKit web Vite example

A minimal, framework-free Vite application that consumes `walletkit-web` as a
published package. It initializes WalletKit in its package-owned Web Worker and
derives authenticator recovery data from a random seed.

Run it from the repository root:

```sh
bun install --cwd examples/web-vite --frozen-lockfile
bun run --cwd examples/web-vite dev
```

Open the local URL printed by Vite, then select **Derive authenticator data**.
Use `bun run --cwd examples/web-vite build` to verify the production bundle.

The example stores its generated database key and storage namespace in
`localStorage` so it can reopen the same encrypted OPFS database after a reload.
This is demo-only key retention: production applications should resolve the key
from a protected source such as passkey PRF.

To test the package from this checkout instead, run `bun run walletkit:local`
from the example directory inside the WASM Nix shell. Run
`bun run walletkit:published` to restore the registry package.
