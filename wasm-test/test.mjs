async function main() {
  const imported = await import('@worldcoin/walletkit-wasm');
  const walletkit =
    typeof imported.uniffiInitAsync === 'function' ? imported : imported.default;

  if (typeof walletkit?.uniffiInitAsync !== 'function') {
    throw new Error('Expected walletkit-wasm to export uniffiInitAsync()');
  }

  await walletkit.uniffiInitAsync();

  if (!walletkit.walletkit_core) {
    throw new Error('Expected walletkit-wasm to export the walletkit_core namespace');
  }

  console.log('walletkit-wasm loaded and initialized successfully');
  console.log('Available walletkit_core exports:', Object.keys(walletkit.walletkit_core).length);
}

main().catch((error) => {
  console.error('walletkit-wasm failed to load or initialize');
  console.error(error);
  process.exit(1);
});
