# walletkit-cli

Developer CLI for WalletKit — primarily used for development, testing, and debugging the World ID authenticator, credential, and proof systems. Not intended for end-user use.

See [TESTING.md](TESTING.md) for a full smoke-test walkthrough.

## Usage

```
walletkit [OPTIONS] <COMMAND>
```

Global options: `--environment` (staging/production), `--json` (machine-readable output), `--root` (custom data dir), `--rpc-url` (World Chain RPC).

## Commands

### `wallet` — Local wallet setup

| Command | Description |
|---|---|
| `init` | Create storage directories and cache Groth16 proving material |
| `paths` | Print resolved storage paths |
| `doctor` | Check wallet health (files, databases, Groth16 cache) |
| `export` | Export vault to a plaintext backup file |
| `import` | Import credentials from a vault backup |
| `danger-clear` | Permanently delete all local data (requires `--confirm`) |

### `auth` — Authenticator lifecycle

| Command | Description |
|---|---|
| `register` | Register a new World ID (returns immediately) |
| `register-wait` | Register and poll until finalized on-chain |
| `init` | Initialize authenticator for an already-registered World ID |
| `info` | Print leaf index, on-chain address, and packed account data |
| `remote-account-data` | Fetch on-chain account data and compare with local |
| `blinding-factor` | Generate a credential blinding factor via OPRF |
| `compute-sub` | Compute a credential sub from a blinding factor |

### `credential` — Credential management

| Command | Description |
|---|---|
| `issue` | Generate blinding factor via OPRF and store a credential |
| `issue-test` | Issue a test credential from the staging faux issuer (schema 128) |
| `import` | Import a credential from a file or stdin |
| `list` | List stored credentials |
| `show` | Show details of the latest credential for an issuer schema |
| `delete` | Delete a credential by ID |

### `proof` — Proof generation and verification

| Command | Description |
|---|---|
| `generate` | Generate a ZK proof from a request JSON |
| `generate-test-request` | Generate a signed test proof request using staging RP keys |
| `inspect-request` | Inspect a proof request without generating a proof |
| `verify` | Verify a proof on-chain via the WorldIDVerifier contract |
