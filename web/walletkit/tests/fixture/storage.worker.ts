// Test the Rust storage directly, independently of network registration.
import init, {
  CredentialStore,
  StorageKeys,
  StoragePaths,
  initializePersistentStorage,
} from "../../src/generated/walletkit.js";
self.onmessage = async ({ data }) => {
  try {
    await init({ module_or_path: new URL(data.wasmUrl) });
    await initializePersistentStorage();
    const keys = StorageKeys.fromBytes(new Uint8Array(32).fill(data.secret));
    const paths = StoragePaths.fromRoot("/walletkit/test-account");
    const store = new CredentialStore(paths, keys);
    try {
      store.init(42n, 1000n);
      self.postMessage({ result: "initialized" });
    } finally {
      store.free();
      paths.free();
      keys.free();
    }
  } catch (error) {
    const e = error as Error & { detail?: string };
    self.postMessage({ error: `${e.name}: ${e.message} (${e.detail})` });
  }
};
