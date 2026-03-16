# walletkit-cli Manual Smoke-Test Guide

Step-by-step checklist for manually verifying all CLI commands against the staging environment.

## Prerequisites

Build the binary:

```bash
cargo build -p walletkit-cli
```

Binary: `./target/debug/walletkit`

Set the RPC URL (used by on-chain commands):

```bash
export WORLDCHAIN_RPC_URL=https://archive.worldchain.worldcoin.org
```

Block explorer (World Chain mainnet, chain ID 480): https://worldscan.org

> **Note:** Staging uses the mainnet chain but routes through staging OPRF/indexer infrastructure.

---

## Section 1 — Wallet setup

Run in order:

```bash
# 1. Show paths before init — no files exist yet
./target/debug/walletkit wallet paths

# 2. Health check — should report missing files
./target/debug/walletkit wallet doctor

# 3. Initialize: create dirs and write embedded Groth16 material to disk
./target/debug/walletkit wallet init

# 4. Health check again — should report healthy
./target/debug/walletkit wallet doctor

# 5. Verify all path keys are present in JSON output
./target/debug/walletkit wallet paths --json
```

**Expected:** `wallet doctor` reports healthy; `wallet paths --json` includes keys
`root`, `worldid_dir`, `vault_db`, `cache_db`, `lock`, `groth16_dir`,
`query_zkey`, `nullifier_zkey`, `query_graph`, `nullifier_graph`.

Verify Groth16 files exist on disk:

```bash
ls ~/.walletkit/groth16/
```

---

## Section 2 — Auth registration (on-chain)

> `wallet init` (Section 1) generates and persists a seed at `~/.walletkit/seed`.
> All commands below automatically read this seed — no `--seed` or `--random-seed` needed.

```bash
# 1. Register and poll until finalized (seed read from ~/.walletkit/seed).
./target/debug/walletkit auth register-wait --environment staging

# 2. Re-running register is idempotent — prints "Already registered."
./target/debug/walletkit auth register-wait --environment staging

# 3. Print leaf index and onchain address for the registered account
./target/debug/walletkit auth info

# 4. Compare local packed account data with on-chain state
./target/debug/walletkit auth remote-account-data \
  --environment staging \
  --rpc-url $WORLDCHAIN_RPC_URL
```

**Expected:** `remote-account-data` prints both values with `Match: yes`.

**Block explorer verification:** Look up the `onchain_address` from step 3 on
https://worldscan.org to confirm the account is visible on-chain.

---

## Section 3 — Credential management

```bash
# 1. List credentials — should be empty
./target/debug/walletkit credential list

# 2. Same in JSON — should return an empty array
./target/debug/walletkit credential list --json

# 3. OPRF round-trip: generate a blinding factor for an issuer schema
#    Replace <ISSUER_SCHEMA_ID> with a valid numeric ID (e.g. 1)
./target/debug/walletkit credential blinding-factor \
  --issuer-schema-id <ISSUER_SCHEMA_ID> \
  --environment staging

# 4. Compute a credential sub from the blinding factor
./target/debug/walletkit credential compute-sub \
  --blinding-factor <BLINDING_FACTOR_FROM_STEP_3>

# 5. Delete a nonexistent credential (should succeed or return a clear error)
./target/debug/walletkit credential delete \
  --credential-id 99999
```

> `credential issue` is covered in Section 4 using the faux issuer.
>
> `credential import` requires a credential payload with a blinding factor from
> a real issuer and is not covered by this standalone smoke test.

---

## Section 4 — End-to-end proof flow

This section is fully self-contained: it uses the staging faux issuer to obtain
a credential and the built-in `generate-test-request` command to create a proof
request, so no external app integration is needed.

```bash
# 1. Issue a test credential from the faux issuer (OPRF + sub + faux issuer + store in one step)
./target/debug/walletkit credential issue-test \
  --environment staging

# 2. Generate a signed test proof request (uses hardcoded staging RP keys)
./target/debug/walletkit proof generate-test-request \
  --issuer-schema-id 128 \
  > request.json

# 3. Parse and inspect the proof request
./target/debug/walletkit proof inspect-request --request request.json

# 4. Generate a ZK proof (writes response JSON to stdout)
./target/debug/walletkit proof generate \
  --request request.json \
  --environment staging \
  > response.json

# 5. Verify the proof on-chain via the WorldIDVerifier contract
./target/debug/walletkit proof verify \
  --request request.json \
  --response response.json \
  --rpc-url $WORLDCHAIN_RPC_URL
```

**Expected:** `proof verify` prints `All proofs verified on-chain.` and exits 0.

**Block explorer verification:** Look up the verifier contract
`0x703a6316c975DEabF30b637c155edD53e24657DB` on https://worldscan.org.

---

## Section 5 — Export / Import roundtrip

```bash
# 1. Export vault to a backup file (--dest is a directory; the file name is generated)
./target/debug/walletkit wallet export --dest /tmp

# 2. Initialize a second wallet at a different root
./target/debug/walletkit --root /tmp/walletkit-test2 wallet init

# 3. Import the backup into the second wallet (use the path printed by export)
./target/debug/walletkit --root /tmp/walletkit-test2 wallet import \
  --backup /tmp/vault_backup_plaintext_<UUID>.sqlite

# 4. Verify credentials are present in the imported wallet.
#    The imported vault was created with the original wallet's seed,
#    so override the test2 seed with the original one.
./target/debug/walletkit --root /tmp/walletkit-test2 credential list \
  --seed "$(cat ~/.walletkit/seed)"
```

---

## Section 6 — Cleanup

```bash
# Remove ALL local state from the default wallet root. Irreversible.
./target/debug/walletkit wallet danger-clear --confirm

# Clean up the test wallet too
./target/debug/walletkit --root /tmp/walletkit-test2 wallet danger-clear --confirm
```

---

## Verification

Confirm the binary builds and the help text is accessible:

```bash
cargo build -p walletkit-cli && ./target/debug/walletkit --help
```
