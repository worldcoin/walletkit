import { initializeWalletKit } from "../../dist/index.js";
Object.assign(window, { initializeWalletKit });
Object.assign(window, {
  storageOperation(operation: string, secret = 7) {
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
        operation,
        secret,
        wasmUrl: new URL("../../dist/generated/walletkit.wasm", import.meta.url)
          .href,
      });
    });
  },
});
