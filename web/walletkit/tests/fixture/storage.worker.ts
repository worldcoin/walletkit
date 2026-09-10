// Test the exported Rust components directly, independently of network registration.
import * as b from "../../src/generated";
self.onmessage = async ({ data }) => {
  try {
    await b.uniffiInitAsync(new URL(data.wasmUrl));
    await b.initializePersistentStorage();
    const keys = b.StorageKeys.fromBytes(
      new Uint8Array(32).fill(data.secret).buffer,
    );
    const paths = b.StoragePaths.fromRoot("/test-account");
    const store = new b.CredentialStore(paths, keys);
    (keys as unknown as { uniffiDestroy(): void }).uniffiDestroy();
    (paths as unknown as { uniffiDestroy(): void }).uniffiDestroy();
    try {
      store.init(42n, 1000n);
      self.postMessage({ result: "initialized" });
    } finally {
      store.uniffiDestroy();
    }
  } catch (error) {
    self.postMessage({ error: String(error) });
  }
};
