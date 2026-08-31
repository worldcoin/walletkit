import { privateKeyToAccount } from "viem/accounts";

import type {
  AuthenticatorLike,
  CredentialStoreLike,
  WalletKit,
} from "walletkit-web";

const FAUX_ISSUER_SCHEMA_ID = 128n;
const STAGING_RP_ID = 46n;
const STAGING_RP_PRIVATE_KEY =
  "0x1111111111111111111111111111111111111111111111111111111111111111";

function fixedWidthBytes(value: bigint, width: number) {
  const bytes = new Uint8Array(width);
  for (let index = width - 1; index >= 0; index -= 1) {
    bytes[index] = Number(value & 0xffn);
    value >>= 8n;
  }
  return bytes;
}

function hex(bytes: Uint8Array) {
  return `0x${Array.from(bytes, (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("")}`;
}

function concat(...chunks: Uint8Array[]) {
  const result = new Uint8Array(
    chunks.reduce((length, chunk) => length + chunk.length, 0),
  );
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.length;
  }
  return result;
}

export async function issueFauxCredential(
  module: WalletKit,
  authenticator: AuthenticatorLike,
  store: CredentialStoreLike,
) {
  const blindingFactor =
    await authenticator.generateCredentialBlindingFactorRemote(
      FAUX_ISSUER_SCHEMA_ID,
    );
  const sub = authenticator.computeCredentialSub(blindingFactor);
  const response = await fetch("/api/faux-credential", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ sub: sub.toHexString() }),
  });
  if (!response.ok) {
    throw new Error(
      `Faux issuer returned ${response.status}: ${await response.text()}`,
    );
  }

  const credential = module.Credential.fromIssuanceResponseBytes(
    await response.arrayBuffer(),
  );
  const now = BigInt(Math.floor(Date.now() / 1000));
  const credentialId = store.storeCredential(
    credential,
    blindingFactor,
    credential.expiresAt(),
    undefined,
    now,
  );

  return {
    credentialId,
    issuerSchemaId: credential.issuerSchemaId(),
    sub: sub.toHexString(),
  };
}

export async function createStagingProofRequest(
  module: WalletKit,
  signal: string,
) {
  const nonce = crypto.getRandomValues(new Uint8Array(32));
  // A 31-byte random value is always within the BabyJubJub base field.
  nonce[0] = 0;
  const action = fixedWidthBytes(1n, 32);
  const createdAt = BigInt(Math.floor(Date.now() / 1000));
  const expiresAt = createdAt + 300n;
  const message = concat(
    new Uint8Array([1]),
    nonce,
    fixedWidthBytes(createdAt, 8),
    fixedWidthBytes(expiresAt, 8),
    action,
  );
  const account = privateKeyToAccount(STAGING_RP_PRIVATE_KEY);
  const signature = await account.signMessage({ message: { raw: message } });

  return module.ProofRequest.fromJson(
    JSON.stringify({
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
          issuer_schema_id: Number(FAUX_ISSUER_SCHEMA_ID),
          signal: hex(new TextEncoder().encode(signal)),
          genesis_issued_at_min: null,
          expires_at_min: null,
        },
      ],
    }),
  );
}
