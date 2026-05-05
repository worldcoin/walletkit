const walletkitCore = require('./out-node/pkg/generated/walletkit_core.js');

async function uniffiInitAsync() {
  walletkitCore.default.initialize();
}

module.exports = {
  ...walletkitCore,
  walletkit_core: walletkitCore,
  uniffiInitAsync,
  default: {
    walletkit_core: walletkitCore,
  },
};
