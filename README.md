# Issuers SDK — Host-mediated UniFFI experiment

This experiment proves that a base Rust library can compose with multiple **separately compiled**
Rust implementation libraries without using a Rust-native trait ABI across binaries.
The domain is World ID credential issuance, inspired by the `oxide` crate's Orb relay and NFC
uniqueness-service pathways.

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│  host-python/main.py  (Python harness)                           │
│                                                                  │
│  IssuerHost ◄── OrbKitAdapter ──► OrbIssuer  (orb-kit cdylib)   │
│            ◄── NfcKitAdapter  ──► NfcIssuer  (nfc-kit cdylib)   │
│                                                                  │
│  issuer-host cdylib  ─── IssuerDriver (UniFFI callback trait)    │
└──────────────────────────────────────────────────────────────────┘
                    shared source dep ▼
                     issuer-sdk (rlib)
              CredentialRequest · Credential · SdkError
```

### Crates

| Crate | Role |
|---|---|
| `crates/issuer-sdk` | Shared domain types (`CredentialRequest`, `Credential`, `SdkError`) and JSON helpers. Compiled as a **source dependency** — not a cross-binary ABI. |
| `crates/issuer-host` | Host orchestrator `cdylib`. Exports `IssuerHost` and the `IssuerDriver` UniFFI callback trait. |
| `crates/orb-kit` | Orb issuance `cdylib`. `OrbIssuer::fetch_credential_async` simulates the Orb relay ZKP handshake. |
| `crates/nfc-kit` | NFC issuance `cdylib`. `NfcIssuer::fetch_credential_async` simulates the NFC PCP decrypt/verify flow. |
| `crates/uniffi-bindgen` | Workspace-local UniFFI binding generation binary. |

### Domain types (`issuer-sdk`)

```rust
pub enum IssuerType { Orb, Nfc }

pub struct CredentialRequest {
    pub user_id: String,      // nullifier hash / World ID commitment stub
    pub issuer_type: IssuerType,
}

pub struct Credential {
    pub id: String,           // UUID
    pub issuer: String,       // "orb-kit" | "nfc-kit"
    pub data: String,         // SD-JWT stub
}
```

### How the host-mediated composition works

1. Python creates `IssuerHost`, `OrbIssuer`, and `NfcIssuer`.
2. Python wraps each issuer in an `IssuerDriver` adapter (`OrbKitAdapter` / `NfcKitAdapter`).
3. `IssuerHost` stores the adapters behind `Arc<dyn IssuerDriver>`.
4. At runtime, Python chooses which issuer name to call.
5. `IssuerHost::fetch_credential_with` uses `tokio::task::spawn_blocking` to invoke the blocking adapter.
6. Each adapter uses `asyncio.run_coroutine_threadsafe` to bridge back into the issuer's async UniFFI method.
7. The issuer performs genuine Tokio async work (network stub) before returning the JSON credential.

## Build and generate Python bindings

From the repository root:

```bash
./generate_python_bindings.sh
```

That script:

- builds the Rust workspace in release mode
- generates Python bindings for `issuer_host`, `orb_kit`, and `nfc_kit`
- copies each native library beside its generated Python module

## Run the demo

```bash
python3 host-python/main.py orb-kit user-abc
python3 host-python/main.py nfc-kit user-xyz
```

Example output:

```json
{"id":"<uuid>","issuer":"orb-kit","data":"eyJhbGciOiJFUzI1NiIsInR5cCI6IlNELUpXVCJ9.stub.orb.user-abc"}
{"id":"<uuid>","issuer":"nfc-kit","data":"eyJhbGciOiJFUzI1NiIsInR5cCI6IlNELUpXVCJ9.stub.nfc.user-xyz"}
```

## Notes

- The Rust-to-host boundary uses JSON `String` payloads intentionally, to keep the experiment
  focused on host-mediated composition across separate binaries.
- `issuer-sdk` is reused as a **source dependency** by all Rust crates, not as a cross-binary ABI.
- `issuer-host::IssuerDriver` stays synchronous so Python can implement the UniFFI foreign trait
  with adapters.
- `orb-kit` and `nfc-kit` keep their own async APIs, allowing real async work without blocking
  Tokio worker threads in `issuer-host`.
- In production, `OrbIssuer` would perform the full ZKP proof generation + PoP backend exchange
  (see `generate_auth_proof`, `pop_backend_api` in oxide), and `NfcIssuer` would decrypt the
  Personal Custody Package and call `/v2/decrypt-pcp-keys` (see `nfc_backend_api` in oxide).
