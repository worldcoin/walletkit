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
    // Byte arguments are copied and the copies transferred: the caller's array
    // stays intact and usable.
    const seed = new Uint8Array(32).fill(1);
    await wallet.recoveryDataFromSeed(seed);
    const seedIntact =
      seed.byteLength === 32 && seed.every((b: number) => b === 1);
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
    return { identities, error, closed, seedIntact };
  });
  expect(result.identities[0].authenticatorAddress).not.toEqual(
    result.identities[1].authenticatorAddress,
  );
  expect(result.error).toContain("InvalidInput");
  expect(result.seedIntact).toBe(true);
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

test("initializing right after a close waits for the pool instead of failing", async ({
  page,
}) => {
  const result = await page.evaluate(async () => {
    const w = window as any;
    const first = await w.initializeWalletKit();
    await first.close();
    // No retry here: the worker retries the OPFS install while the closed worker's
    // handles are released.
    const second = await w.initializeWalletKit();
    await second.close();
    return "reopened";
  });
  expect(result).toBe("reopened");
});

test("proxies belong to the instance that created them", async ({ page }) => {
  const result = await page.evaluate(async () => {
    const w = window as any;
    const first = await w.initializeWalletKit();
    const keys = await first.StorageKeys.fromBytes(new Uint8Array(32).fill(1));
    await first.close();
    const second = await w.initializeWalletKit();
    try {
      const paths = await second.StoragePaths.fromRoot("/walletkit/owner");
      const foreign = await second.CredentialStore.new(paths, keys).catch(
        (e: Error) => `${e.name}: ${e.message}`,
      );
      const outOfRange = await second.FieldElement.fromU64(
        2n ** 64n + 7n,
      ).catch((e: Error) => `${e.name}: ${e.message}`);
      return { foreign, outOfRange };
    } finally {
      await second.close();
    }
  });
  expect(result.foreign).toBe(
    "TypeError: This WalletKit object belongs to a different WalletKit instance",
  );
  expect(result.outOfRange).toMatch(/^TypeError: `value` must be a bigint/);
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

test("abort cancels initialization with the signal's reason", async ({
  page,
}) => {
  const result = await page.evaluate(async () => {
    const w = window as any;
    const aborted = async (reason?: unknown) => {
      const controller = new AbortController();
      const pending = w.initializeWalletKit({ signal: controller.signal });
      controller.abort(reason);
      return pending.catch((e: unknown) => e);
    };
    const byDefault = await aborted();
    return {
      defaultName: (byDefault as Error).name,
      custom: await aborted("navigation"),
    };
  });
  // The caller sees the signal's own reason, so cancellation is detectable.
  expect(result.defaultName).toBe("AbortError");
  expect(result.custom).toBe("navigation");
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
    const code = await wallet.FieldElement.fromBytes(new Uint8Array(2)).catch(
      (e: Error & { code?: string }) => e.code,
    );
    const keys = await wallet.StorageKeys.fromBytes(new Uint8Array(32).fill(3));
    const paths = await wallet.StoragePaths.fromRoot("/walletkit/args");
    const store = await wallet.CredentialStore.new(paths, keys);
    const query = await wallet.ActivityQuery.new();
    const negativeLimit = await capture(store.listActivities(query, -1, 0));
    await wallet.close();
    return {
      invalidSeed,
      invalidKey,
      invalidCredential,
      unknownEnvironment,
      code,
      negativeLimit,
    };
  });
  expect(result.invalidSeed.name).toBe("WalletKitError");
  expect(result.invalidSeed.message).toMatch(/InvalidInput \{/);
  expect(result.code).toBe("InvalidInput");
  expect(result.negativeLimit.name).toBe("TypeError");
  expect(result.negativeLimit.message).toContain("limit");
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
    const query = await wallet.ActivityQuery.new();
    const activities = await store.listActivities(query, 10, 0);
    const filtered = await store.listActivities(
      await query.withIssuerSchemaId(3n),
      10,
      0,
    );
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
      filtered,
      metadata,
      sameRoot,
      released,
    };
  });
  expect(result.hex).toMatch(/ff$/);
  expect(result.roundTripLength).toBe(32);
  expect(result.credentials).toEqual([]);
  expect(result.activities).toHaveLength(1);
  expect(result.filtered).toEqual([]);
  expect(result.activities[0]).toMatchObject({
    id: result.activityId,
    appIdentifier: "app_test",
    protocol: 4,
    outcome: "completed",
    issuerSchemaIds: [1n, 2n],
  });
  expect(result.metadata).toEqual({ totalCount: 1n });
  expect(result.sameRoot).toBe("/walletkit/handles");
  expect(result.released).toContain("freed");
});

test("close frees live objects, is idempotent and rejects later calls", async ({
  page,
}) => {
  const result = await page.evaluate(async () => {
    const wallet = await (window as any).initializeWalletKit();
    const element = await wallet.FieldElement.fromU64(1n);
    const first = wallet.close();
    const second = wallet.close();
    await Promise.all([first, second]);
    const afterClose = await element
      .toHexString()
      .catch((e: Error) => e.message);
    return { sameClose: first === second, afterClose };
  });
  expect(result.sameClose).toBe(true);
  expect(result.afterClose).toContain("closed");
});

test("the worker only dispatches functions and methods the module exports", async ({
  page,
}) => {
  // Learn the packaged worker and Wasm URLs from a first run, then release the pool.
  let workerUrl = "";
  let wasmUrl = "";
  page.on("worker", (worker) => (workerUrl = worker.url()));
  page.on("request", (request) => {
    if (request.url().endsWith(".wasm")) wasmUrl = request.url();
  });
  await page.evaluate(async () => {
    const wallet = await (window as any).initializeWalletKit();
    await wallet.close();
  });
  await expect(async () => {
    const result = await page.evaluate(
      async ({ workerUrl, wasmUrl }) => {
        const worker = new Worker(workerUrl, { type: "module" });
        let nextId = 0;
        const send = (message: object) =>
          new Promise<any>((resolve) => {
            const id = nextId++;
            worker.onmessage = ({ data }) => data.id === id && resolve(data);
            worker.postMessage({ ...message, id });
          });
        try {
          const initialized = await send({ op: "initialize", wasmUrl });
          if (!initialized.ok) throw new Error(initialized.error.message);
          const call = (target: object, args: unknown[] = []) =>
            send({ op: "call", target, args });
          const created = await call(
            { class: "FieldElement", static: "fromU64" },
            [5n],
          );
          const handle = created.result.$ref;
          return {
            allowed: (await call({ handle, method: "toHexString" })).ok,
            free: await call({ handle, method: "free" }),
            destroy: await call({ handle, method: "__destroy_into_raw" }),
            wrap: await call({ class: "FieldElement", static: "__wrap" }, [1]),
            internal: await call({ function: "initializePersistentStorage" }),
            startFn: await call({ function: "start" }),
            unknownClass: await call({ class: "toString", static: "call" }),
            stillAlive: (await call({ handle, method: "toHexString" })).ok,
          };
        } finally {
          worker.terminate();
        }
      },
      { workerUrl, wasmUrl },
    );
    expect(result.allowed).toBe(true);
    for (const rejected of [
      result.free,
      result.destroy,
      result.wrap,
      result.internal,
      result.startFn,
      result.unknownClass,
    ]) {
      expect(rejected.ok).toBe(false);
      expect(rejected.error.message).toMatch(/^Unknown /);
    }
    expect(result.stillAlive).toBe(true);
  }).toPass({ timeout: 5000 });
});
