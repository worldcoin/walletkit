# WalletKit Agent Guidelines

## UniFFI Naming

Never name a UniFFI-exported method `to_string`. UniFFI maps Rust's `to_string` to Kotlin's `toString`, which conflicts with `Any.toString()` and causes a compilation error (`'toString' hides member of supertype 'Any' and needs 'override' modifier`). Use a descriptive name instead (e.g., `to_hex_string`, `to_decimal_string`, `to_json`).

## Coding style

- **On-disk format is byte-stable.** Schemas, CBOR layouts, and `compute_content_id` derivations are part of the contract. Existing user databases must keep opening without migration; guard format-sensitive code with frozen-byte tests next to it.
- **Don't layer a flock around SQLite writes.** WAL mode serializes writers itself. The `Lock` primitive is only for the envelope-init bootstrap and operations that mix SQL with filesystem state.
- **Per-consumer isolation is host wiring.** Separate keystore entry, AD label, and envelope/vault/lock files. `walletkit-db` enforces only the AEAD-AD binding.
- **`walletkit-db` is consumer-agnostic.** It owns `blob_objects` and the storage primitives (vault, envelope, lock, traits). Credential-specific tables, schemas, and APIs live in `walletkit-core/storage/credential_vault`. Don't put consumer logic in `walletkit-db`, and don't put primitives in consumer crates.
- **`#[expect(lint, reason = "...")]` over `#[allow(lint)]`.** `#[expect]` fails to compile when the suppression is no longer needed, so dead suppressions don't accumulate.
- **Inline single-consumer helper modules.** A `mod foo;` file with `pub(super) fn`s used only by its parent adds boundary without payoff; put the functions as private free `fn`s at the bottom of the parent module.
- **Colocate constants with the code that reads them, not their conceptual home.** A `const` used only by `mod.rs` belongs in `mod.rs`, not in a sibling `schema.rs`.
- **Tests live next to the code they test.** One `#[cfg(test)] mod tests` per source file, including inside `cfg`-gated blocks. For code gated by `#[cfg(not(target_arch = "wasm32"))]` (e.g. `Lock`'s native `imp` module), tests go inside that same block so they only compile for the platform they cover.
