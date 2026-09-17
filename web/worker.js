import init, { FlamingoClient } from './pkg/walletkit_web.js';

const ready = init();
let client;
let nextHandle = 0;
const verified = new Map();

function dispose() {
  client?.free();
  client = undefined;
  for (const token of verified.values()) token.free();
  verified.clear();
}

self.onmessage = async ({ data: { id, operation, payload } }) => {
  try {
    await ready;
    let result;
    switch (operation) {
      case 'initialize': {
        const replacement = new FlamingoClient(payload);
        dispose();
        client = replacement;
        result = { ready: true };
        break;
      }
      case 'match': {
        if (!client) throw Object.assign(new Error('Initialize the client first'), { code: 'configuration' });
        const outcome = await client.performMatch(payload);
        try {
          const token = outcome.verified;
          const handle = token ? ++nextHandle : undefined;
          if (token) verified.set(handle, token);
          result = { matched: outcome.matched, rejection: outcome.rejection, verifiedHandle: handle };
        } finally {
          outcome.free();
        }
        break;
      }
      case 'release':
        verified.get(payload)?.free();
        verified.delete(payload);
        result = { released: true };
        break;
      default:
        throw Object.assign(new Error('Unknown operation'), { code: 'invalid_input' });
    }
    self.postMessage({ id, result });
  } catch (error) {
    self.postMessage({ id, error: {
      code: error?.code ?? 'worker',
      message: error?.code ? error.message : 'Browser operation failed',
    } });
  }
};
