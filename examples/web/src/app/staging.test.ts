import { expect, test } from "bun:test";
import { recoverMessageAddress } from "viem";
import { privateKeyToAccount } from "viem/accounts";

import { FAUX_ISSUER_SCHEMA_ID, createStagingProofRequest } from "./staging";

// The intentionally public staging RP key (shared with walletkit-testkit).
const STAGING_RP_SIGNER = privateKeyToAccount(
  "0x1111111111111111111111111111111111111111111111111111111111111111",
).address;

const bytes = (hex: string) =>
  Uint8Array.from(Buffer.from(hex.slice(2), "hex"));
const be = (value: number, width: number) => {
  const out = new Uint8Array(width);
  let rest = BigInt(value);
  for (let index = width - 1; index >= 0; index -= 1) {
    out[index] = Number(rest & 0xffn);
    rest >>= 8n;
  }
  return out;
};

test("the staging proof request is well formed and signed by the RP", async () => {
  const before = Math.floor(Date.now() / 1000);
  const request = JSON.parse(await createStagingProofRequest("signal"));

  expect(request).toMatchObject({
    version: 1,
    proof_type: "uniqueness",
    rp_id: "rp_000000000000002e",
    oprf_key_id: "0x2e",
    session_id: null,
  });
  expect(request.created_at).toBeGreaterThanOrEqual(before);
  expect(request.expires_at - request.created_at).toBe(300);
  // Core's wire name for the credential requests.
  expect(request.proof_requests).toEqual([
    {
      identifier: "faux-credential",
      issuer_schema_id: Number(FAUX_ISSUER_SCHEMA_ID),
      signal: `0x${Buffer.from("signal").toString("hex")}`,
      genesis_issued_at_min: null,
      expires_at_min: null,
    },
  ]);
  // A 31-byte nonce is always inside the field.
  expect(request.nonce).toMatch(/^0x00[0-9a-f]{62}$/);

  // The signature covers version || nonce || created_at || expires_at || action.
  const message = Uint8Array.from([
    1,
    ...bytes(request.nonce),
    ...be(request.created_at, 8),
    ...be(request.expires_at, 8),
    ...bytes(request.action),
  ]);
  expect(
    await recoverMessageAddress({
      message: { raw: message },
      signature: request.signature,
    }),
  ).toBe(STAGING_RP_SIGNER);
});

test("each staging proof request gets a fresh id and nonce", async () => {
  const [first, second] = await Promise.all([
    createStagingProofRequest("signal").then(JSON.parse),
    createStagingProofRequest("signal").then(JSON.parse),
  ]);
  expect(first.id).not.toBe(second.id);
  expect(first.nonce).not.toBe(second.nonce);
});
