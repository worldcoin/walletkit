# WalletKit Agent Guidelines

## UniFFI Naming

Never name a UniFFI-exported method `to_string`. UniFFI maps Rust's `to_string` to Kotlin's `toString`, which conflicts with `Any.toString()` and causes a compilation error (`'toString' hides member of supertype 'Any' and needs 'override' modifier`). Use a descriptive name instead (e.g., `to_hex_string`, `to_decimal_string`, `to_json`).

## On-disk format is byte-stable

Schemas, CBOR envelope layout, the `compute_content_id` derivation (`SHA-256(b"worldid:blob" || [kind] || plaintext)`), and the `account_keys.bin` filename / `worldid:account-key-envelope` AD tag are part of the on-disk contract. Existing user databases must keep opening without migration. Frozen-byte tests guard these: `walletkit-db/src/blobs.rs` (content_id), `walletkit-db/src/envelope.rs` (CBOR), `walletkit-core/src/storage/credential_vault/tests.rs::test_credential_vault_on_disk_format_guard` (credential schema + kind tag). Any change that updates one of these hex strings needs an on-disk format review, not a fresh hex commit.

## AEAD terminology

When documenting envelope or page encryption, name the AEAD primitive (`ChaCha20-Poly1305`, `AES-GCM`) rather than writing "encrypt" or "authenticate". The host `Keystore` trait requires an AEAD construction; the contract dies if a non-AEAD impl is plugged in.

## `aad` not `associated_data`

The AEAD term clashes with `BlobKind::AssociatedData` (the credential-vault blob kind). Use `aad` for AEAD-parameter names and doc text; reserve `associated_data` for the unrelated credential-vault concept.

## SQLite WAL serializes writers; don't layer flock

`Vault::connection()` exposes `&Connection`; `walletkit-db` does NOT wrap mutations in a cross-process lock. SQLite in WAL mode handles writer serialization itself. The `Lock` primitive is only for (a) the envelope-init bootstrap race inside `init_or_open_envelope_key` and (b) operations that mix SQL with filesystem state (plaintext export / import, `destroy_storage`). Don't add a flock around ordinary writes.

## Per-consumer isolation lives in host wiring

If a second consumer (e.g. OrbKit's PCP store) shares the device with `walletkit-core`'s credential vault, the host must provide: a separate hardware keystore entry, a separate AD label, and separate envelope / vault / lock filenames. `walletkit-db` enforces only the AEAD-AD binding; sharing a keystore entry across consumers breaks isolation.
