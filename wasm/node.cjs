const walletkitCore = require('./out-node/pkg/generated/walletkit_core.js');

// The wasm-bindgen `nodejs` target loads the WASM module synchronously from the
// generated CommonJS glue. Initialize the UniFFI bindings synchronously too, so
// consumers can use the package immediately after import/require.
walletkitCore.default.initialize();

module.exports = {
  ...walletkitCore,
  walletkit_core: walletkitCore,
  default: {
    walletkit_core: walletkitCore,
  },
};
