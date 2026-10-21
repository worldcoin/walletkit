import { randomBytes } from "node:crypto";

import { expect, test, type Browser, type Page } from "@playwright/test";

// WIP-109 end to end against staging: two browsers pair through the staging message-bridge,
// and the approver inserts the new authenticator through the staging gateway on World Chain.
// Like the Rust registration integration test, it always runs and needs the network.

const BRIDGE_DOMAIN = "staging-bridge.worldcoin.org";
const RPC_URL =
  process.env.WORLDCHAIN_RPC_URL || "https://rpc.worldchain.worldcoin.org";

/** Opens a page in its own context, so each device has its own WalletKit storage. */
async function openDevice(browser: Browser, baseURL: string | undefined) {
  const context = await browser.newContext({ baseURL });
  const page = await context.newPage();
  await page.goto("/");
  await page.waitForFunction(() => "initializeWalletKit" in window);
  await page.evaluate(
    async ({ seed, storageKey, root }) => {
      const w = window as any;
      w.seed = () => new Uint8Array(seed);
      w.wallet = await w.initializeWalletKit();
      const keys = await w.wallet.StorageKeys.fromBytes(
        new Uint8Array(storageKey),
      );
      const paths = await w.wallet.StoragePaths.fromRoot(root);
      w.store = await w.wallet.CredentialStore.new(paths, keys);
      w.artifacts = await w.wallet.EmbeddedZkArtifacts.new();
    },
    {
      seed: [...randomBytes(32)],
      storageKey: [...randomBytes(32)],
      root: "/walletkit/registration",
    },
  );

  return page;
}

async function closeDevice(page: Page) {
  await page.evaluate(() => (window as any).wallet?.close());
  await page.context().close();
}

/** Registers a new account for the device's seed and opens its Admin Authenticator. */
async function registerAccount(page: Page) {
  return page.evaluate(async (rpcUrl) => {
    const w = window as any;
    const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
    const registration =
      await w.wallet.InitializingAuthenticator.registerWithDefaults(
        w.seed(),
        rpcUrl,
        "staging",
        "us",
        "0x0000000000000000000000000000000000000000",
      );

    for (;;) {
      const status = await registration.pollStatus();
      if (status.state === "finalized") break;
      if (status.state === "failed") {
        throw new Error(`account registration failed: ${status.error}`);
      }
      await sleep(1000);
    }

    // The RPC node may lag the finalized block.
    for (let attempt = 1; ; attempt += 1) {
      try {
        w.authenticator = await w.wallet.Authenticator.initWithDefaults(
          w.seed(),
          rpcUrl,
          "staging",
          "us",
          w.artifacts,
          w.store,
        );
        break;
      } catch (e: any) {
        if (e.code !== "AccountDoesNotExist" || attempt === 10) throw e;
        await sleep(2000);
      }
    }

    const leafIndex: bigint = await w.authenticator.leafIndex();
    await w.store.init(leafIndex, BigInt(Math.floor(Date.now() / 1000)));
    return leafIndex;
  }, RPC_URL);
}

/** Polls the requester until its status is no longer `current`. */
async function pollPast(page: Page, current: string) {
  return page.evaluate(async (current) => {
    const w = window as any;
    for (;;) {
      const status = await w.requester.poll();
      if (status.state !== current) {
        w.lastStatus = status;
        return { state: status.state as string, error: status.error };
      }
      await new Promise((r) => setTimeout(r, 500));
    }
  }, current);
}

test("an admin authenticator in one browser registers a proving authenticator in another", async ({
  browser,
  baseURL,
}) => {
  test.setTimeout(3 * 60_000);

  const approving = await openDevice(browser, baseURL);
  const requesting = await openDevice(browser, baseURL);
  try {
    const leafIndex = await registerAccount(approving);

    // The devices meet only through the QR code and the pairing code the user types.
    const uri = await requesting.evaluate(async (domain) => {
      const w = window as any;
      const bridge = await w.wallet.BridgeClient.new(domain);
      w.requester = await w.wallet.RegistrationRequester.start(
        w.seed(),
        "proving",
        "Chrome on MacBook",
        bridge,
      );
      return w.requester.pairingUri() as Promise<string>;
    }, BRIDGE_DOMAIN);

    await approving.evaluate(
      async ({ uri, domain }) => {
        const w = window as any;
        const bridge = await w.wallet.BridgeClient.new(domain);
        w.pending = await w.wallet.PendingRegistration.receive(uri, bridge);
      },
      { uri, domain: BRIDGE_DOMAIN },
    );

    expect(await pollPast(requesting, "waiting")).toEqual({
      state: "retrieved",
    });
    const code = await requesting.evaluate(
      () => (window as any).requester.pairingCode() as Promise<string>,
    );

    const checked = await approving.evaluate(async (code) => {
      const w = window as any;
      const incoming = await w.pending.authenticate(code);
      w.checked = await incoming.check(w.authenticator);
      return {
        class: await w.checked.class(),
        name: await w.checked.name(),
        plan: await w.checked.plan(),
      };
    }, code);
    expect(checked).toEqual({
      class: "proving",
      name: "Chrome on MacBook",
      plan: { kind: "insert", pubkeyId: 1 },
    });

    // `approve` holds the approver's worker until the insertion is final, while the
    // requester keeps polling from its own.
    const [outcome, approved] = await Promise.all([
      approving.evaluate(async () => {
        const w = window as any;
        const response = await fetch("/backups/local-backup.sqlite");
        const vault = new Uint8Array(await response.arrayBuffer());
        return w.checked.approve(w.authenticator, vault, [
          { pubkeyId: 0, name: "iPhone" },
        ]);
      }),
      pollPast(requesting, "retrieved"),
    ]);
    expect(outcome).toEqual({
      result: { state: "registered", leafIndex, pubkeyId: 1 },
      vaultOmitted: false,
      delivered: true,
    });
    expect(approved).toEqual({ state: "approved" });

    const registered = await requesting.evaluate(async (rpcUrl) => {
      const w = window as any;
      const result = w.lastStatus.result;
      const unverified = {
        leafIndex: await result.leafIndex(),
        pubkeyId: await result.pubkeyId(),
        authenticators: await result.authenticators(),
        hasVault: await result.hasVault(),
      };

      const now = BigInt(Math.floor(Date.now() / 1000));
      const registered = await w.requester.verifyWithDefaults(
        w.seed(),
        result,
        rpcUrl,
        "staging",
        "us",
        w.artifacts,
        w.store,
      );
      await registered.authenticator.initStorage(now);
      const added = await w.store.mergeVaultFromBackup(registered.vaultBackup);
      const credentials = await w.store.listCredentials(undefined, 1000n);

      const restarted =
        await w.wallet.Authenticator.initWithLeafIndexAndDefaults(
          w.seed(),
          unverified.leafIndex,
          rpcUrl,
          "staging",
          "us",
          w.artifacts,
          w.store,
        );

      return {
        unverified,
        leafIndex: await registered.authenticator.leafIndex(),
        added,
        credentials: credentials.length,
        restartedLeafIndex: await restarted.leafIndex(),
      };
    }, RPC_URL);
    expect(registered).toEqual({
      unverified: {
        leafIndex,
        pubkeyId: 1,
        authenticators: [{ pubkeyId: 0, name: "iPhone" }],
        hasVault: true,
      },
      leafIndex,
      added: 1n,
      credentials: 1,
      restartedLeafIndex: leafIndex,
    });
  } finally {
    await Promise.all([closeDevice(approving), closeDevice(requesting)]);
  }
});
