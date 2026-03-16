# walletkit-cli Known Bugs

## BUG-001: `register-wait` idempotency check fails with error instead of "Already registered."

**Command:** `walletkit auth register-wait --environment staging`

**Expected:** When the account is already registered, prints `Already registered.` and exits 0.

**Actual:** Returns exit code 1 with:
```
Error: registration failed: network_error at gateway: {"code":"authenticator_already_exists","message":"authenticator_already_exists"}
```

**Root cause:** The CLI handles `WalletKitError::AccountAlreadyExists` correctly in `auth.rs`, but the gateway's `authenticator_already_exists` error code is not being mapped to that variant in the core library — it surfaces as a raw `network_error` instead.

**Affected:** `auth register` and `auth register-wait` (both share the same code path)

---

## BUG-002: `wallet import` requires a registered account unnecessarily

**Command:** `walletkit --root /tmp/walletkit-test2 wallet import --backup <file>`

**Expected:** Imports the backup into the target wallet regardless of registration state.

**Actual:** Fails with `authenticator init failed: Account is not registered for this authenticator.` when the target wallet has a fresh unregistered seed.

**Root cause:** `run_import` calls `init_authenticator` which contacts the server to verify the account is registered. The import operation only needs the credential store (`create_fs_credential_store`), not the authenticator.

**Workaround:** Pass the original wallet's seed via `--seed "$(cat ~/.walletkit/seed)"` so the authenticator can init against the registered account.
