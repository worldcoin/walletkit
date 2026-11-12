import { initializeWalletKit } from "../../dist/index.js";
Object.assign(window, { initializeWalletKit });
Object.assign(window, {
  storageOperation(secret = 7) {
    const worker = new Worker(new URL("./storage.worker.ts", import.meta.url), {
      type: "module",
    });
    return new Promise((resolve, reject) => {
      worker.onmessage = ({ data }) => {
        worker.terminate();
        data.error ? reject(new Error(data.error)) : resolve(data.result);
      };
      worker.onerror = (event) => {
        worker.terminate();
        reject(new Error(event.message));
      };
      worker.postMessage({
        secret,
        wasmUrl: new URL("../../src/generated/walletkit.wasm", import.meta.url)
          .href,
      });
    });
  },
});

Object.assign(window, {
  enrollmentAssignment() {
    const worker = new Worker(
      new URL("./enrollment.worker.ts", import.meta.url),
      { type: "module" },
    );
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        worker.terminate();
        reject(new Error("Enrollment did not reject the untrusted assignment"));
      }, 5000);
      worker.onmessage = ({ data }) => {
        clearTimeout(timeout);
        worker.terminate();
        data.error ? reject(new Error(data.error)) : resolve(data.result);
      };
      worker.onerror = (event) => {
        clearTimeout(timeout);
        worker.terminate();
        reject(new Error(event.message));
      };
      worker.postMessage({
        wasmUrl: new URL("../../src/generated/walletkit.wasm", import.meta.url)
          .href,
      });
    });
  },
});
