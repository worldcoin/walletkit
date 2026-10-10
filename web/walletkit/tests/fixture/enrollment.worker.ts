import init, {
  extractSelfieEmbedding,
  sanitizeHexSecrets,
} from "../../src/generated/walletkit.js";

self.onmessage = async ({ data }) => {
  try {
    await init({ module_or_path: new URL(data.wasmUrl) });
    const sent: string[] = [];
    let closed = false;
    Object.assign(self, {
      WebSocket: class {
        static OPEN = 1;
        readyState = 1;
        bufferedAmount = 0;
        onopen?: (event: Event) => void;
        onmessage?: (event: MessageEvent) => void;
        constructor() {
          setTimeout(() => this.onopen?.(new Event("open")), 0);
        }
        send(value: unknown) {
          sent.push(
            typeof value === "string" ? JSON.parse(value).type : "image",
          );
          setTimeout(
            () =>
              this.onmessage?.(
                new MessageEvent("message", {
                  data: JSON.stringify({
                    type: "assignment",
                    attestation: "AQ==",
                    public_key: "Ag==",
                  }),
                }),
              ),
            0,
          );
        }
        close() {
          this.readyState = 3;
          closed = true;
        }
      },
    });
    const config = {
      endpoint: "wss://enrollment.invalid/v1/embeddings",
      releases: [
        {
          pcr0: "1".repeat(96),
          pcr1: "2".repeat(96),
          pcr2: "3".repeat(96),
          worker_sha384: "4".repeat(96),
        },
      ],
    };
    let code;
    try {
      await extractSelfieEmbedding(JSON.stringify(config), new Uint8Array([1]));
    } catch (error) {
      code = (error as Error & { code?: string }).code;
    }
    self.postMessage({
      result: { code, sent, closed, alive: sanitizeHexSecrets("alive") },
    });
  } catch (error) {
    self.postMessage({ error: String(error) });
  }
};
