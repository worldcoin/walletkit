// Test the exported Rust components directly, independently of network registration.
import * as b from "../../src/generated";
self.onmessage = async ({ data }) => {
  try {
    await b.uniffiInitAsync(new URL(data.wasmUrl));
    await b.initializePersistentStorage();
    if (data.operation === "init") {
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
      return;
    }
    const secretKeystore = new b.SecretDeviceKeystore(
      new Uint8Array(32).fill(data.secret).buffer,
    );
    const ks = secretKeystore.asDeviceKeystore();
    secretKeystore.uniffiDestroy();
    const sqliteBlobs = new b.SqliteAtomicBlobStore("/test-envelopes.sqlite");
    const blobs = sqliteBlobs.asAtomicBlobStore();
    sqliteBlobs.uniffiDestroy();
    const aad = new TextEncoder().encode("test-ad").buffer;
    let result: unknown;
    switch (data.operation) {
      case "write":
        blobs.writeAtomic(
          "envelope",
          ks.seal(aad, new Uint8Array([0, 1, 255]).buffer),
        );
        result = "written";
        break;
      case "read":
        result = Array.from(
          new Uint8Array(ks.openSealed(aad, blobs.read("envelope")!)),
        );
        break;
      case "delete":
        blobs.delete_("envelope");
        result = blobs.read("envelope") === undefined;
        break;
      case "init-envelope": {
        const paths = b.StoragePaths.fromRoot("/test-envelope-account");
        const keys = b.StorageKeys.fromEnvelope(paths, ks, blobs, 1000n);
        const store = new b.CredentialStore(paths, keys);
        (keys as unknown as { uniffiDestroy(): void }).uniffiDestroy();
        (paths as unknown as { uniffiDestroy(): void }).uniffiDestroy();
        store.init(42n, 1000n);
        result = "initialized";
        break;
      }
    }
    self.postMessage({ result });
  } catch (error) {
    self.postMessage({ error: String(error) });
  }
};
