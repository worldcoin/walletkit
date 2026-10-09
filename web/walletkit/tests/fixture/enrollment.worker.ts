import init, { extractSelfieEmbedding, sanitizeHexSecrets } from "../../src/generated/walletkit.js";

self.onmessage = async ({ data }) => {
  try {
    await init({ module_or_path: new URL(data.wasmUrl) });
    let aborted = false;
    let imageSent = false;
    let reads = 0;
    const mockFetch = async (request: Request) => {
      request.signal.addEventListener("abort", () => { aborted = true; });
      return new Response(new ReadableStream({
        pull(controller) {
          reads++;
          // Never close: the client must reject the first excess byte without waiting for EOF.
          if (reads <= 3) controller.enqueue(new Uint8Array(data.largeChunk ? 1024 * 1024 : (reads === 3 ? 1 : 1024)));
        },
      }), { status: 200 });
    };
    Object.assign(self, {
      fetch: mockFetch,
      WebSocket: class {
        static OPEN = 1;
        readyState = 1;
        bufferedAmount = 0;
        onopen?: (event: Event) => void;
        onmessage?: (event: MessageEvent) => void;
        constructor() {
          setTimeout(() => {
            this.onopen?.(new Event("open"));
            this.onmessage?.(new MessageEvent("message", { data: JSON.stringify({
              type: "admission", data: { audience: "test", nonce: Array(32).fill(1) },
            }) }));
          }, 0);
        }
        send(value: unknown) { if (typeof value !== "string") imageSent = true; }
        close() { this.readyState = 3; }
      },
    });
    const config = { endpoint: "wss://enrollment.invalid/v1/embeddings", audience: "test", releases: [{
      pcr0: "1".repeat(96), pcr1: "2".repeat(96), pcr2: "3".repeat(96), worker_sha384: "4".repeat(96),
    }] };
    let code;
    try { await extractSelfieEmbedding(JSON.stringify(config), new Uint8Array([1]), "/admission-test"); }
    catch (error) { code = (error as Error & { code?: string }).code; }
    self.postMessage({ result: { code, aborted, imageSent, reads, alive: sanitizeHexSecrets("alive") } });
  } catch (error) {
    self.postMessage({ error: String(error) });
  }
};
