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
    const wallet = await w.initializeWalletKit();
    const identities = await Promise.all([
      wallet.recoveryDataFromSeed(new Uint8Array(32).fill(1)),
      wallet.recoveryDataFromSeed(new Uint8Array(32).fill(2)),
    ]);
    const error = await wallet.FieldElement.fromBytes(new Uint8Array(2)).catch(
      (e: Error) => e.message,
    );
    await wallet.close();
    const closed = await wallet
      .recoveryDataFromSeed(new Uint8Array(32))
      .catch((e: Error) => e.message);
    return { identities, error, closed };
  });
  expect(result.identities[0].authenticatorAddress).not.toEqual(
    result.identities[1].authenticatorAddress,
  );
  expect(result.error).toContain("InvalidInput");
  expect(result.closed).toContain("closed");
});

test("second owner fails and storage can reopen after close", async ({
  page,
}) => {
  await page.evaluate(async () => {
    const w = window as any;
    w.wallet = await w.initializeWalletKit();
  });
  const error = await page.evaluate(async () => {
    const w = window as any;
    return w.initializeWalletKit().then(
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
      const wallet = await (window as any).initializeWalletKit();
      await wallet.close();
    });
  }).toPass({ timeout: 5000 });
});

test("encrypted databases reopen with a directly supplied key", async ({
  page,
}) => {
  const init = (databaseKey: number) =>
    page.evaluate(
      (databaseKey) => (window as any).storageOperation(databaseKey),
      databaseKey,
    );
  expect(await init(7)).toBe("initialized");
  await expect(async () => {
    expect(await init(7)).toBe("initialized");
  }).toPass({ timeout: 5000 });
  await expect(async () => {
    await expect(init(8)).rejects.toThrow(/StorageError: vault db error/);
  }).toPass({ timeout: 5000 });
});

test("abort cancels initialization", async ({ page }) => {
  const result = await page.evaluate(async () => {
    const w = window as any;
    const controller = new AbortController();
    const pending = w.initializeWalletKit({ signal: controller.signal });
    controller.abort();
    return pending.catch((e: Error) => e.message);
  });
  expect(result).toContain("terminated");
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
    const wallet = await (window as any).initializeWalletKit();
    await wallet.close();
  });
  expect(workerUrl).toContain("walletkit.worker");
  expect(wasmUrl).toContain(".wasm");
  await expect(async () => {
    await page.evaluate(
      async ({ workerUrl, wasmUrl }) => {
        const wallet = await (window as any).initializeWalletKit({
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
      .initializeWalletKit({ workerUrl: "/missing-worker.js" })
      .catch((e: Error) => e.message);
  });
  expect(result).toContain("worker");
});

test("Rust errors keep their name and variant detail across the worker", async ({
  page,
}) => {
  const result = await page.evaluate(async () => {
    const w = window as any;
    const wallet = await w.initializeWalletKit();
    const capture = (promise: Promise<unknown>) =>
      promise.then(
        () => ({ name: "none", message: "unexpected success" }),
        (e: Error) => ({ name: e.name, message: e.message }),
      );
    const invalidSeed = await capture(
      wallet.recoveryDataFromSeed(new Uint8Array(2)),
    );
    const invalidKey = await capture(
      wallet.StorageKeys.fromBytes(new Uint8Array(2)),
    );
    const invalidCredential = await capture(
      wallet.Credential.fromBytes(new Uint8Array([1, 2, 3])),
    );
    const unknownEnvironment = await capture(
      wallet.pohRecoveryAgentAddress("moon"),
    );
    await wallet.close();
    return { invalidSeed, invalidKey, invalidCredential, unknownEnvironment };
  });
  expect(result.invalidSeed.name).toBe("WalletKitError");
  expect(result.invalidSeed.message).toMatch(/InvalidInput \{/);
  expect(result.invalidKey.name).toBe("StorageError");
  expect(result.invalidCredential.name).toBe("WalletKitError");
  expect(result.unknownEnvironment).toEqual({
    name: "TypeError",
    message: "Unknown environment: moon",
  });
});

test("Rust objects stay in the worker and are used through handles", async ({
  page,
}) => {
  const result = await page.evaluate(async () => {
    const w = window as any;
    const wallet = await w.initializeWalletKit();
    const element = await wallet.FieldElement.fromU64(255n);
    const hex = await element.toHexString();
    const roundTrip = await (
      await wallet.FieldElement.tryFromHexString(hex)
    ).toBytes();

    const keys = await wallet.StorageKeys.fromBytes(new Uint8Array(32).fill(9));
    const paths = await wallet.StoragePaths.fromRoot("/walletkit/handles");
    const store = await wallet.CredentialStore.new(paths, keys);
    await store.init(42n, 1000n);
    const credentials = await store.listCredentials(undefined, 1000n);
    const entry = {
      rpId: 1n,
      appIdentifier: "app_test",
      clientId: "client",
      protocol: 4,
      outcome: "completed",
      issuerSchemaIds: [1n, 2n],
    };
    const activityId = await store.recordActivity(entry, 1000n);
    const activities = await store.listActivities({}, 10, 0);
    const metadata = await store.activityMetadata();
    const sameRoot = await (await store.storagePaths()).rootPathString();

    element.free();
    const released = await element.toHexString().catch((e: Error) => e.message);
    await wallet.close();
    return {
      hex,
      roundTripLength: roundTrip.length,
      credentials,
      activityId,
      activities,
      metadata,
      sameRoot,
      released,
    };
  });
  expect(result.hex).toMatch(/ff$/);
  expect(result.roundTripLength).toBe(32);
  expect(result.credentials).toEqual([]);
  expect(result.activities).toHaveLength(1);
  expect(result.activities[0]).toMatchObject({
    id: result.activityId,
    appIdentifier: "app_test",
    protocol: 4,
    outcome: "completed",
    issuerSchemaIds: [1n, 2n],
  });
  expect(result.metadata).toEqual({ totalCount: 1n });
  expect(result.sameRoot).toBe("/walletkit/handles");
  expect(result.released).toContain("released");
});
