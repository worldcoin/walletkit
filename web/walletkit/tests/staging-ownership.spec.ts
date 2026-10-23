import { writeFileSync } from "node:fs";
import { expect, test } from "@playwright/test";

// Generates an ownership proof in the browser for a registered staging account.
// Opt-in: it needs staging network access and writes the proof for native verification by
// `cargo test -p walletkit-core --test ownership_cross_target` with the same WALLETKIT_STAGING_PROOF.
test.skip(!process.env.WALLETKIT_STAGING_PROOF, "set WALLETKIT_STAGING_PROOF");
test.setTimeout(180_000);

test("proveCredentialSub generates an ownership proof in the browser", async ({
  page,
}) => {
  await page.goto("/");
  await page.waitForFunction(() => "initializeWalletKit" in window);

  const result = await page.evaluate(async () => {
    const w = window as any;
    const wallet = await w.initializeWalletKit();
    const keys = await wallet.StorageKeys.fromBytes(new Uint8Array(32).fill(3));
    const paths = await wallet.StoragePaths.fromRoot(
      "/walletkit/staging-ownership",
    );
    const store = await wallet.CredentialStore.new(paths, keys);
    const artifacts = await wallet.EmbeddedZkArtifacts.new();
    const authenticator = await wallet.Authenticator.initWithDefaults(
      new Uint8Array(32).fill(19),
      undefined,
      "staging",
      "us",
      artifacts,
      store,
    );
    await authenticator.initStorage(BigInt(Math.floor(Date.now() / 1000)));

    const blindingFactor = await wallet.FieldElement.fromU64(999n);
    const sub = await authenticator.computeCredentialSub(blindingFactor);
    const nonce = await wallet.FieldElement.fromU64(1_234_567_890n);
    const context = await wallet.FieldElement.fromU64(42n);

    const start = performance.now();
    const proof: Uint8Array = await authenticator.proveCredentialSub(
      nonce,
      context,
      blindingFactor,
      sub,
    );
    const elapsedMs = performance.now() - start;

    const hex = (bytes: Uint8Array) =>
      Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
    const out = {
      proof: hex(proof),
      sub: await sub.toHexString(),
      nonce: await nonce.toHexString(),
      context: await context.toHexString(),
      elapsedMs,
    };
    await authenticator.destroyStorage();
    await wallet.close();
    return out;
  });

  expect(result.proof.length).toBeGreaterThan(0);
  writeFileSync(process.env.WALLETKIT_STAGING_PROOF!, JSON.stringify(result));
});
