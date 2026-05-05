# walletkit-wasm Node.js smoke test

This directory is a small local Node.js project that imports the local
`@worldcoin/walletkit-wasm` package and verifies the Node.js WASM build loads.

From the repository root:

```bash
cd wasm
npm ci
npm run build:node

cd ../wasm-test
npm install
npm test
```

The dependency is local (`"@worldcoin/walletkit-wasm": "file:../wasm"`), so run
`npm install` in this directory again after rebuilding the package if needed.
