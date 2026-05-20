# WalletKit Agent Guidelines

## UniFFI Naming

Never name a UniFFI-exported method `to_string`. UniFFI maps Rust's `to_string` to Kotlin's `toString`, which conflicts with `Any.toString()` and causes a compilation error (`'toString' hides member of supertype 'Any' and needs 'override' modifier`). Use a descriptive name instead (e.g., `to_hex_string`, `to_decimal_string`, `to_json`).

## Code style

- **On-disk format is byte-stable.** Schemas, CBOR layouts, and `compute_content_id` derivations are part of the contract. Existing user databases must keep opening without migration; guard format-sensitive code with frozen-byte tests next to it.
- **Name the AEAD primitive** (`ChaCha20-Poly1305`, `AES-GCM`) in crypto docs instead of "encrypt" / "authenticate". The `Keystore` trait requires AEAD.
- **Use `aad` for AEAD parameter names.** `associated_data` is taken by `BlobKind::AssociatedData`.
- **Don't layer a flock around SQLite writes.** WAL mode serializes writers itself. The `Lock` primitive is only for the envelope-init bootstrap and operations that mix SQL with filesystem state.
- **Per-consumer isolation is host wiring.** Separate keystore entry, AD label, and envelope/vault/lock files. `walletkit-db` enforces only the AEAD-AD binding.
