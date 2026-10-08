# Plaintext vault merge fixtures

These SQLite databases use the unconstrained tables produced by native backup
export (`CREATE TABLE AS SELECT`). All data is synthetic. Credential blob bytes
are markers for storage tests, not serialized protocol credentials.

- `local-backup.sqlite`: one credential, issuer 1, row ID 1.
- `incoming-backup.sqlite`: one credential, issuer 2, also row ID 1, to check that
  merging preserves local IDs and allocates a fresh ID for incoming records.
- `invalid-backup.sqlite`: issuer 3 plus a record referencing a missing blob, to
  check that invalid backups leave no partial additions.

All records have genesis/updated time 100, expiry 999999, and a 32-byte blinding
factor repeating the issuer byte. Blob bytes contain the issuer byte; content IDs
are SHA-256 of `worldid:blob`, byte 1 (credential kind), then those blob bytes.
