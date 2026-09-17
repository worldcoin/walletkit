// Local example/test server. It does not implement or proxy biometric verification.
import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { resolve, extname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('.', import.meta.url));
const types = { '.html': 'text/html', '.js': 'text/javascript', '.wasm': 'application/wasm' };
const server = http.createServer(async (request, response) => {
  const pathname = new URL(request.url, 'http://localhost').pathname;
  // Tests reach the real browser Fetch path. This deliberately invalid attestation must fail.
  if (process.env.WALLETKIT_BROWSER_TEST === '1' && pathname === '/v1/enclave-assignment') {
    response.writeHead(200, {
      'Content-Type': 'application/json', 'Cache-Control': 'no-store',
      'Set-Cookie': 'flamingo_test=assigned; Path=/; HttpOnly; SameSite=Lax',
    });
    response.end(JSON.stringify({ attestation: 'AA==', public_key: 'AA==' }));
    return;
  }
  const file = resolve(root, `.${pathname === '/' ? '/index.html' : pathname}`);
  if (!file.startsWith(root) || !['GET', 'HEAD'].includes(request.method)) {
    response.writeHead(404).end();
    return;
  }
  try {
    const content = await readFile(file);
    response.writeHead(200, { 'Content-Type': types[extname(file)] ?? 'application/octet-stream', 'Cache-Control': 'no-store' });
    response.end(request.method === 'HEAD' ? undefined : content);
  } catch {
    response.writeHead(404).end();
  }
});
server.listen(Number(process.env.PORT ?? 4173), '127.0.0.1');
