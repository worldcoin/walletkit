import { expect, test } from "@playwright/test";

test.beforeEach(async ({ page }) => {
  await page.goto("/");
  await page.waitForFunction(() => "initializeWalletKit" in window);
});

test("packaged worker initializes, correlates calls, reports errors and closes", async ({
  page,
}) => {
  const result = await page.evaluate(async () => {
    const w = window as any;
    const wallet = await w.initializeWalletKit({
      databaseKey: new Uint8Array(32).fill(7),
    });
    const identities = await Promise.all([
      wallet.recoveryDataFromSeed(new Uint8Array(32).fill(1)),
      wallet.recoveryDataFromSeed(new Uint8Array(32).fill(2)),
    ]);
    const error = await wallet
      .pollRegistration()
      .catch((e: Error) => e.message);
    await wallet.close();
    const closed = await wallet
      .recoveryDataFromSeed(new Uint8Array(32))
      .catch((e: Error) => e.message);
    return { identities, error, closed };
  });
  expect(result.identities[0].authenticatorAddress).not.toEqual(
    result.identities[1].authenticatorAddress,
  );
  expect(result.error).toContain("Start registration");
  expect(result.closed).toContain("closed");
});

test("second owner fails and storage can reopen after close", async ({
  page,
}) => {
  await page.evaluate(async () => {
    const w = window as any;
    w.wallet = await w.initializeWalletKit({
      databaseKey: new Uint8Array(32).fill(7),
    });
  });
  const error = await page.evaluate(async () => {
    const w = window as any;
    return w
      .initializeWalletKit({ databaseKey: new Uint8Array(32).fill(7) })
      .then(
        (client: any) => {
          client.terminate();
          return "unexpected success";
        },
        (e: Error) => e.message,
      );
  });
  expect(error).not.toBe("unexpected success");
  await page.evaluate(async () => {
    await (window as any).wallet.close();
  });
  // Browser worker termination releases handles asynchronously.
  await expect(async () => {
    await page.evaluate(async () => {
      const wallet = await (window as any).initializeWalletKit({
        databaseKey: new Uint8Array(32).fill(7),
      });
      await wallet.close();
    });
  }).toPass({ timeout: 5000 });
});

test("Rust SQLite blobs persist across workers and reject a wrong wrapping key", async ({
  page,
}) => {
  const operation = (name: string, databaseKey = 7) =>
    page.evaluate(
      ([name, databaseKey]) =>
        (window as any).storageOperation(name, databaseKey),
      [name, databaseKey] as const,
    );
  expect(await operation("write")).toBe("written");
  await expect(async () => {
    expect(await operation("read")).toEqual([0, 1, 255]);
  }).toPass({ timeout: 5000 });
  await expect(async () => {
    await expect(operation("read", 8)).rejects.toThrow(/Crypto|authentication/);
  }).toPass({ timeout: 5000 });
  await expect(async () => {
    expect(await operation("delete")).toBe(true);
  }).toPass({ timeout: 5000 });
});

test("encrypted databases reopen with a directly supplied key", async ({
  page,
}) => {
  const init = (databaseKey: number) =>
    page.evaluate(
      (databaseKey) => (window as any).storageOperation("init", databaseKey),
      databaseKey,
    );
  expect(await init(7)).toBe("initialized");
  await expect(async () => {
    expect(await init(7)).toBe("initialized");
  }).toPass({ timeout: 5000 });
  await expect(async () => {
    await expect(init(8)).rejects.toThrow(/StorageError.VaultDb/);
  }).toPass({ timeout: 5000 });
});

test("abort cancels initialization and invalid secrets do not spawn a worker", async ({
  page,
}) => {
  const result = await page.evaluate(async () => {
    const w = window as any;
    const invalid = await w
      .initializeWalletKit({ databaseKey: new Uint8Array(2) })
      .catch((e: Error) => e.message);
    const controller = new AbortController();
    const pending = w.initializeWalletKit({
      databaseKey: new Uint8Array(32),
      signal: controller.signal,
    });
    controller.abort();
    return { invalid, aborted: await pending.catch((e: Error) => e.message) };
  });
  expect(result.invalid).toContain("32-byte");
  expect(result.aborted).toContain("terminated");
});

test("custom worker and Wasm URLs load the same runtime", async ({ page }) => {
  let workerUrl = "";
  let wasmUrl = "";
  page.on("worker", (worker) => {
    workerUrl = worker.url();
  });
  page.on("request", (request) => {
    if (request.url().endsWith(".wasm")) wasmUrl = request.url();
  });
  await page.evaluate(async () => {
    const wallet = await (window as any).initializeWalletKit({
      databaseKey: new Uint8Array(32).fill(7),
    });
    await wallet.close();
  });
  expect(workerUrl).toContain("walletkit.worker");
  expect(wasmUrl).toContain(".wasm");
  await expect(async () => {
    await page.evaluate(
      async ({ workerUrl, wasmUrl }) => {
        const wallet = await (window as any).initializeWalletKit({
          databaseKey: new Uint8Array(32).fill(7),
          workerUrl,
          wasmUrl,
        });
        await wallet.close();
      },
      { workerUrl, wasmUrl },
    );
  }).toPass({ timeout: 5000 });
});

test("a worker load failure rejects initialization", async ({ page }) => {
  const result = await page.evaluate(async () => {
    return (window as any)
      .initializeWalletKit({
        databaseKey: new Uint8Array(32),
        workerUrl: "/missing-worker.js",
      })
      .catch((e: Error) => e.message);
  });
  expect(result).toContain("worker");
});

test("host-resolved envelope keys still reopen encrypted storage", async ({
  page,
}) => {
  const init = (secret: number) =>
    page.evaluate(
      (secret) => (window as any).storageOperation("init-envelope", secret),
      secret,
    );
  expect(await init(7)).toBe("initialized");
  await expect(async () => {
    expect(await init(7)).toBe("initialized");
  }).toPass({ timeout: 5000 });
  await expect(async () => {
    await expect(init(8)).rejects.toThrow(/StorageError.Keystore/);
  }).toPass({ timeout: 5000 });
});
