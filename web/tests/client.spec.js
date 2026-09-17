import { test, expect } from '@playwright/test';

test.beforeEach(async ({ page }) => { await page.goto('/'); });

test('worker initializes with approved-shaped pins and rejects invalid input before upload', async ({ page }) => {
  const uploads = [];
  page.on('request', request => { if (request.method() === 'POST') uploads.push(request.url()); });
  const result = await page.evaluate(async () => {
    const { FlamingoWorker } = await import('/client.js');
    const client = new FlamingoWorker();
    try {
      const initialized = await client.initialize({ hostUrl: location.origin,
        measurements: { 0: '01'.repeat(48), 1: '02'.repeat(48), 2: '03'.repeat(48) } });
      try {
        await client.match({ liveImage: new Uint8Array(), credentialImage: new Uint8Array([1]),
          hashesJson: new Uint8Array([2]), challengeImage: new Uint8Array([3]), matchThreshold: .5 });
      } catch (error) { return { initialized, code: error.code }; }
    } finally { client.close(); }
  });
  expect(result).toEqual({ initialized: { ready: true }, code: 'invalid_input' });
  expect(uploads).toEqual([]);
});

test('invalid pins and caller cookies fail configuration', async ({ page }) => {
  const codes = await page.evaluate(async () => {
    const { FlamingoWorker } = await import('/client.js');
    const client = new FlamingoWorker();
    const codes = [];
    try {
      for (const config of [
        { measurements: {} },
        { measurements: { 0: '00'.repeat(48), 1: '02'.repeat(48), 2: '03'.repeat(48) } },
        { measurements: { 0: '01'.repeat(48), 1: '02'.repeat(48), 2: '03'.repeat(48) }, headers: { Cookie: 'forbidden' } },
      ]) {
        try { await client.initialize({ hostUrl: location.origin, ...config }); }
        catch (error) { codes.push(error.code); }
      }
    } finally { client.close(); }
    return codes;
  });
  expect(codes).toEqual(['configuration', 'configuration', 'configuration']);
});

test('real Fetch rejects an untrusted assignment before any biometric upload', async ({ page, context }) => {
  const posts = [];
  page.on('request', request => { if (request.method() === 'POST') posts.push({ url: request.url(), body: request.postData() }); });
  const result = await page.evaluate(async () => {
    const { FlamingoWorker } = await import('/client.js');
    const client = new FlamingoWorker();
    try {
      await client.initialize({ hostUrl: location.origin,
        measurements: { 0: '01'.repeat(48), 1: '02'.repeat(48), 2: '03'.repeat(48) } });
      try {
        await client.match({ liveImage: new Uint8Array([1]), credentialImage: new Uint8Array([2]),
          hashesJson: new Uint8Array([3]), challengeImage: new Uint8Array([4]), matchThreshold: .5 });
      } catch (error) { return { code: error.code, message: error.message }; }
    } finally { client.close(); }
  });
  expect(result.code).toBe('verifier');
  expect(result.message).not.toContain('http');
  expect(posts).toHaveLength(1);
  expect(posts[0].url).toContain('/v1/enclave-assignment');
  expect(posts[0].body).toBeNull();
  expect((await context.cookies()).some(cookie => cookie.name === 'flamingo_test')).toBe(true);
});

test('closing the worker settles pending initialization and rejects later requests', async ({ page }) => {
  const messages = await page.evaluate(async () => {
    const { FlamingoWorker } = await import('/client.js');
    const client = new FlamingoWorker();
    const pending = client.initialize({});
    client.close();
    const result = [];
    for (const operation of [pending, client.match({})]) {
      try { await operation; } catch (error) { result.push(error.message); }
    }
    return result;
  });
  expect(messages).toEqual(['Client closed', 'Client is closed']);
});
