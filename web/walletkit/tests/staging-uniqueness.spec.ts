import { expect, test } from "@playwright/test";
import { privateKeyToAccount } from "viem/accounts";

// Generates uniqueness proofs in the browser for a registered staging account.
// Opt-in: it needs staging network access. Every OPRF call (the blinding factor and each proof)
// combines node answers with an ark-ec MSM. For about half of the node combinations the
// Lagrange coefficients are full-width scalars, the input that panics on wasm32 when
// `ark-ec/parallel` is enabled, so the test makes enough calls to hit that case.
test.skip(
  !process.env.WALLETKIT_STAGING_UNIQUENESS,
  "set WALLETKIT_STAGING_UNIQUENESS",
);
test.setTimeout(600_000);

const PROOFS = 8;
const FAUX_ISSUER_URL = "https://faux-issuer.us.id-infra.worldcoin.dev/issue";
const FAUX_ISSUER_SCHEMA_ID = 128;
// The staging RP that examples/web signs its requests with (examples/web/src/app/staging.ts).
const STAGING_RP_ID = 46n;
const STAGING_RP_PRIVATE_KEY =
  "0x1111111111111111111111111111111111111111111111111111111111111111";

test("generateProof survives repeated OPRF calls in the browser", async ({
  page,
  request,
}) => {
  // A panic usually rejects the pending call first; print it so the failure shows the cause.
  const panics: string[] = [];
  page.on("console", (message) => {
    if (!message.text().includes("panicked at")) return;
    panics.push(message.text());
    console.error(message.text());
  });

  await page.goto("/");
  await page.waitForFunction(() => "initializeWalletKit" in window);

  const sub = await page.evaluate(async (issuerSchemaId) => {
    const w = window as any;
    const wallet = await w.initializeWalletKit();
    const keys = await wallet.StorageKeys.fromBytes(new Uint8Array(32).fill(4));
    const paths = await wallet.StoragePaths.fromRoot(
      "/walletkit/staging-uniqueness",
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
    const blindingFactor =
      await authenticator.generateCredentialBlindingFactorRemote(
        BigInt(issuerSchemaId),
      );
    const sub = await authenticator.computeCredentialSub(blindingFactor);
    w.staging = { wallet, store, authenticator, blindingFactor };
    return sub.toHexString();
  }, FAUX_ISSUER_SCHEMA_ID);

  const issued = await request.post(FAUX_ISSUER_URL, { data: { sub } });
  expect(issued.ok(), await issued.text()).toBe(true);
  const credential = credentialJson(await issued.text());

  await page.evaluate(async (credential) => {
    const { wallet, store, blindingFactor } = (window as any).staging;
    const parsed = await wallet.Credential.fromBytes(
      new TextEncoder().encode(credential),
    );
    await store.storeCredential(
      parsed,
      blindingFactor,
      await parsed.expiresAt(),
      undefined,
      BigInt(Math.floor(Date.now() / 1000)),
    );
  }, credential);

  for (let index = 0; index < PROOFS; index += 1) {
    const proofRequest = await stagingProofRequest(`walletkit-web-${index}`);
    await page.evaluate(async (proofRequest) => {
      const { wallet, authenticator } = (window as any).staging;
      const parsed = await wallet.ProofRequest.fromJson(proofRequest);
      const response = await authenticator.generateProof(parsed);
      response.free();
      parsed.free();
    }, proofRequest);
  }

  await page.evaluate(async () => {
    const { wallet, authenticator } = (window as any).staging;
    await authenticator.destroyStorage();
    await wallet.close();
  });
  expect(panics).toEqual([]);
});

/** Re-serializes the issuer's credential without rounding its large integers. */
function credentialJson(responseBody: string) {
  const { rawJSON } = JSON as unknown as { rawJSON(text: string): unknown };
  const body = JSON.parse(
    responseBody,
    (_key, value, context?: { source: string }) =>
      typeof value === "number" && context ? rawJSON(context.source) : value,
  );
  if (body?.credential === undefined) {
    throw new Error(`Faux issuer response has no credential: ${responseBody}`);
  }
  return JSON.stringify(body.credential);
}

/** A uniqueness proof request for the faux credential, signed by the staging RP. */
async function stagingProofRequest(signal: string) {
  const nonce = crypto.getRandomValues(new Uint8Array(32));
  // A 31-byte random value is always within the BabyJubJub base field.
  nonce[0] = 0;
  const action = bigEndian(1n, 32);
  const createdAt = BigInt(Math.floor(Date.now() / 1000));
  const expiresAt = createdAt + 300n;
  const message = new Uint8Array([
    1,
    ...nonce,
    ...bigEndian(createdAt, 8),
    ...bigEndian(expiresAt, 8),
    ...action,
  ]);
  const signature = await privateKeyToAccount(
    STAGING_RP_PRIVATE_KEY,
  ).signMessage({ message: { raw: message } });

  return JSON.stringify({
    id: crypto.randomUUID(),
    version: 1,
    proof_type: "uniqueness",
    created_at: Number(createdAt),
    expires_at: Number(expiresAt),
    rp_id: `rp_${STAGING_RP_ID.toString(16).padStart(16, "0")}`,
    oprf_key_id: `0x${STAGING_RP_ID.toString(16)}`,
    session_id: null,
    action: hex(action),
    signature,
    nonce: hex(nonce),
    proof_requests: [
      {
        identifier: "faux-credential",
        issuer_schema_id: FAUX_ISSUER_SCHEMA_ID,
        signal: hex(new TextEncoder().encode(signal)),
        genesis_issued_at_min: null,
        expires_at_min: null,
      },
    ],
  });
}

function bigEndian(value: bigint, width: number) {
  const bytes = new Uint8Array(width);
  for (let index = width - 1; index >= 0; index -= 1) {
    bytes[index] = Number(value & 0xffn);
    value >>= 8n;
  }
  return bytes;
}

function hex(bytes: Uint8Array) {
  return `0x${Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}
