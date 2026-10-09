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
    const runningStopped = wallet.isStopped();
    await wallet.close();
    const closed = await wallet
      .recoveryDataFromSeed(new Uint8Array(32))
      .catch((e: Error) => e.message);
    const other = await w.initializeWalletKit();
    other.terminate();
    return {
      identities,
      error,
      closed,
      seedIntact,
      runningStopped,
      closedStopped: wallet.isStopped(),
      terminatedStopped: other.isStopped(),
    };
  });
  expect(result.identities[0].authenticatorAddress).not.toEqual(
    result.identities[1].authenticatorAddress,
  );
  expect(result.error).toContain("InvalidInput");
  expect(result.seedIntact).toBe(true);
  expect(result.runningStopped).toBe(false);
  expect(result.closedStopped).toBe(true);
  expect(result.terminatedStopped).toBe(true);
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
      // Encoding fails on the foreign proxy after the seed was already copied.
      const seed = new Uint8Array(32).fill(5);
      const mixed = await second
        .checkCredentialsAgainstProofRequest(seed, keys)
        .catch((e: Error) => e.name);
      const seedIntact = seed.every((b: number) => b === 5);
      const outOfRange = await second.FieldElement.fromU64(
        2n ** 64n + 7n,
      ).catch((e: Error) => `${e.name}: ${e.message}`);
      return { foreign, outOfRange, mixed, seedIntact };
    } finally {
      await second.close();
    }
  });
  expect(result.foreign).toBe(
    "TypeError: This WalletKit object belongs to a different WalletKit instance",
  );
  expect(result.outOfRange).toMatch(/^TypeError: `value` must be a bigint/);
  expect(result.mixed).toBe("TypeError");
  expect(result.seedIntact).toBe(true);
});

test("destroying supplied-key storage removes its OPFS files", async ({
  page,
}) => {
  const result = await page.evaluate(async () => {
    const wallet = await (window as any).initializeWalletKit();
    try {
      const root = `/walletkit/destroy-${crypto.randomUUID()}`;
      const open = async (byte: number) => {
        const keys = await wallet.StorageKeys.fromBytes(
          new Uint8Array(32).fill(byte),
        );
        const paths = await wallet.StoragePaths.fromRoot(root);
        return wallet.CredentialStore.new(paths, keys);
      };
      const store = await open(1);
      await store.init(42n, 1000n);
      await store.destroyStorage();
      const reinit = await store.init(42n, 1000n).then(
        () => "reinitialized",
        (e: Error) => e.name,
      );
      // Had the encrypted files survived, a different key could not open them.
      const reopened = await open(2);
      await reopened.init(42n, 1000n);
      return { reinit, reopenedWithAnotherKey: true };
    } finally {
      await wallet.close();
    }
  });
  expect(result.reinit).toBe("StorageError");
  expect(result.reopenedWithAnotherKey).toBe(true);
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

test("logging helpers redact secrets and reach the worker console", async ({
  page,
}) => {
  const secret = "0xde" + "0".repeat(60) + "ef";
  const warnings: string[] = [];
  page.on("console", (message) => {
    if (message.type() === "warning") warnings.push(message.text());
  });
  const result = await page.evaluate(async (secret) => {
    const wallet = await (window as any).initializeWalletKit();
    const redacted = await wallet.sanitizeHexSecrets(`key ${secret}`);
    await wallet.emitLog("warn", `emitted ${secret}`);
    await wallet.emitLog("debug", "dropped below warn");
    const unknownLevel = await wallet
      .emitLog("loud", "message")
      .catch((e: Error) => ({ name: e.name, message: e.message }));
    await wallet.close();
    return { redacted, unknownLevel };
  }, secret);
  expect(result.redacted).toBe("key 0xde..ef");
  expect(result.unknownLevel).toEqual({
    name: "TypeError",
    message: "Unknown log level: loud",
  });
  await expect
    .poll(() => warnings.find((text) => text.includes("emitted")))
    .toContain("emitted 0xde..ef");
  expect(warnings.join("\n")).not.toContain(secret);
  expect(warnings.join("\n")).not.toContain("dropped below warn");
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

test("vault backups merge additively, reject invalid data, and survive reopening", async ({
  page,
}) => {
  const result = await page.evaluate(async () => {
    const w = window as any;
    const wallet = await w.initializeWalletKit();
    const keys = await wallet.StorageKeys.fromBytes(new Uint8Array(32).fill(7));
    const paths = await wallet.StoragePaths.fromRoot("/walletkit/merge-test");
    let store = await wallet.CredentialStore.new(paths, keys);

    const loadBackup = async (name: string) => {
      const response = await fetch(`/backups/${name}.sqlite`);
      if (!response.ok) throw new Error(`backup fixture: ${response.status}`);
      return new Uint8Array(await response.arrayBuffer());
    };

    try {
      // Reject recovery until the store has been initialized.
      const localBackup = await loadBackup("local-backup");
      const uninitializedError = await store
        .mergeVaultFromBackup(localBackup)
        .catch((e: Error) => e.name);

      // Seed the vault with a credential that subsequent merges must preserve.
      await store.init(42n, 1000n);
      const initialAdded = await store.mergeVaultFromBackup(localBackup);
      const localRecords = await store.listCredentials(undefined, 1000n);

      // Reject both invalid database contents and malformed database bytes.
      const invalidContentsError = await store
        .mergeVaultFromBackup(await loadBackup("invalid-backup"))
        .catch((e: Error) => e.name);

      const malformedHeaderError = await store
        .mergeVaultFromBackup(new Uint8Array([1, 2, 3]))
        .catch((e: Error) => e.name);

      // SQLite stores its two-byte page size at header offsets 16–17.
      const badPageSize = localBackup.slice();
      badPageSize[16] = 0;
      badPageSize[17] = 0;
      const invalidPageSizeError = await store
        .mergeVaultFromBackup(badPageSize)
        .catch((e: Error) => e.name);

      // A corrupt schema must not poison the live vault connection.
      const corruptSchema = localBackup.slice();
      corruptSchema[100] = 0xff;
      const invalidSchemaError = await store
        .mergeVaultFromBackup(corruptSchema)
        .catch((e: Error) => e.name);

      const recordsAfterFailure = await store.listCredentials(undefined, 1000n);

      // The incoming record reuses the local row ID; merge must allocate a new one.
      const incomingBackup = await loadBackup("incoming-backup");
      const added = await store.mergeVaultFromBackup(incomingBackup);

      // Replaying the same backup must not duplicate its credential.
      const replayedAdded = await store.mergeVaultFromBackup(incomingBackup);
      const mergedRecords = await store.listCredentials(undefined, 1000n);

      // Reopen the encrypted vault to verify that the merge was persisted.
      store.free();
      store = await wallet.CredentialStore.new(paths, keys);
      await store.init(42n, 1000n);
      const reopenedRecords = await store.listCredentials(undefined, 1000n);

      return {
        uninitializedError,
        initialAdded,
        localRecords,
        invalidContentsError,
        malformedHeaderError,
        invalidPageSizeError,
        invalidSchemaError,
        recordsAfterFailure,
        added,
        replayedAdded,
        mergedRecords,
        reopenedRecords,
      };
    } finally {
      store.free();
      paths.free();
      keys.free();
      await wallet.close();
    }
  });

  expect(result.uninitializedError).toBe("StorageError");
  expect(result.initialAdded).toBe(1n);

  expect(result.invalidContentsError).toBe("StorageError");
  expect(result.malformedHeaderError).toBe("StorageError");
  expect(result.invalidPageSizeError).toBe("StorageError");
  expect(result.invalidSchemaError).toBe("StorageError");
  expect(result.recordsAfterFailure).toEqual(result.localRecords);

  expect(result.added).toBe(1n);
  expect(result.replayedAdded).toBe(0n);
  expect(result.mergedRecords).toHaveLength(2);
  expect(result.mergedRecords).toEqual(
    expect.arrayContaining(result.localRecords),
  );

  expect(result.reopenedRecords).toEqual(result.mergedRecords);
});

test("enrollment rejects invalid policy and cross-origin admission before network access", async ({
  page,
}) => {
  const result = await page.evaluate(async () => {
    const wallet = await (window as any).initializeWalletKit();
    try {
      const policy = await wallet
        .extractSelfieEmbedding("{}", new Uint8Array([1]), "/api/admission")
        .catch((error: Error & { code?: string }) => ({
          name: error.name,
          code: error.code,
        }));
      const path = await wallet
        .extractSelfieEmbedding(
          "{}",
          new Uint8Array([1]),
          "//attacker.example/admission",
        )
        .catch((error: Error) => error.name);
      const escaped = await wallet
        .extractSelfieEmbedding(
          "{}",
          new Uint8Array([1]),
          "/\\attacker.example/admission",
        )
        .catch((error: Error) => error.name);
      return { policy, path, escaped, stopped: wallet.isStopped() };
    } finally {
      await wallet.close();
    }
  });
  expect(result.policy).toEqual({
    name: "SelfieEnrollmentError",
    code: "Config",
  });
  expect(result.path).toBe("TypeError");
  expect(result.escaped).toBe("TypeError");
  expect(result.stopped).toBe(false);
});

for (const largeChunk of [false, true]) {
  test(`enrollment bounds streamed admission before copying ${largeChunk ? "an oversized chunk" : "an extra byte"}`, async ({
    page,
  }) => {
    const result = await page.evaluate(
      (large) => (window as any).enrollmentLimit(large),
      largeChunk,
    );
    expect(result.code).toBe("Admission");
    expect(result.aborted).toBe(true);
    expect(result.imageSent).toBe(false);
    expect(result.alive).toBe("alive");
    expect(result.reads).toBeLessThanOrEqual(largeChunk ? 2 : 4);
  });
}
