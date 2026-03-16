## Summary

This PR adds a CLI for WalletKit. The idea here is to get a CLI that can be used for dev and testing. This is not meant to be used as an authenticator for an actual World ID — the environment defaults to staging.

## Features

### Wallet management (`walletkit wallet`)

- `init` — Bootstrap wallet data directory (`~/.walletkit` by default) with required subdirectories and databases
- `paths` — Print resolved storage paths (useful for debugging and scripting)
- `doctor` — Health check: verifies root exists, Groth16 material is cached, and databases are openable
- `export` — Export the vault to a plaintext backup file
- `import` — Restore credentials from a vault backup file
- `danger-clear` — Permanently delete all credentials (requires `--confirm`)

### Authenticator lifecycle (`walletkit auth`)

- `register` — Submit a new World ID registration (returns immediately)
- `register-wait` — Register and poll until finalized, with configurable interval
- `init` — Initialize an authenticator for an already-registered World ID
- `info` — Print authenticator details (leaf index, onchain address, packed account data)
- `remote-account-data` — Fetch on-chain packed account data and compare with local state

### Credential operations (`walletkit credential`)

- `import` — Import a raw credential with a pre-computed blinding factor
- `issue` — End-to-end credential issuance: generate blinding factor via OPRF, then store
- `issue-test` — Issue a test credential from the staging faux issuer (issuer schema 128) in a single step (OPRF + sub + faux issuer + store)
- `list` — List stored credentials, optionally filtered by issuer schema ID
- `show` — Show details of the latest credential for an issuer schema
- `delete` — Delete a credential by ID
- `blinding-factor` — Generate a credential blinding factor via OPRF nodes
- `compute-sub` — Derive a credential sub from a blinding factor

### Proof generation (`walletkit proof`)

- `generate` — Generate a ZK proof from a proof-request JSON (file or stdin)
- `generate-test-request` — Generate a signed test proof request using hardcoded staging RP keys
- `inspect-request` — Parse and display a proof request without generating a proof
- `verify` — Verify a previously generated proof on-chain via the WorldIDVerifier contract

### Global options

- `--root` / `WALLETKIT_ROOT` — Custom wallet data directory
- `--seed` / `WALLETKIT_SEED` — 32-byte hex authenticator seed
- `--random-seed` — Generate a fresh random seed for quick testing
- `--environment` — Target environment (`staging` or `production`, defaults to staging)
- `--region` — OPRF/indexer region selection (`eu`, `us`, `ap`)
- `--rpc-url` / `WORLDCHAIN_RPC_URL` — World Chain RPC endpoint
- `--json` — Machine-readable JSON output for all commands
- `--verbose` — Enable debug logging
- `--config` / `WALLETKIT_CONFIG` — Path to a custom config JSON file (overrides `--environment` and `--region`)
- `--latency` — Print per-network-call latency summary after the command

### `proof verify` options

- `--verifier-address` — Override the WorldID verifier contract address (default: mainnet); useful for testnet
