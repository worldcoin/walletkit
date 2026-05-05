async function main() {
  const imported = await import('@worldcoin/walletkit-wasm');
  const walletkit = imported.walletkit_core ? imported : imported.default;

  if (!walletkit?.walletkit_core) {
    throw new Error('Expected walletkit-wasm to export the walletkit_core namespace');
  }

  console.log('walletkit-wasm loaded successfully');
  console.log('Available walletkit_core exports:', Object.keys(walletkit.walletkit_core).length);
}

main().catch((error) => {
  console.error('walletkit-wasm failed to load');
  console.error(error);
  process.exit(1);
});
