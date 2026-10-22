# Generate a proof

A relying party asks for a World ID proof by sending a proof request. This page
shows how a WalletKit app answers it with a registered account. To register an
account and store credentials first, see
[Accounts and credentials](accounts.md).

## Before you begin

- Enable the `embed-zkeys` feature, which provides the proving keys. See
  [Install WalletKit](installation.md#rust).
- Open the account's `CredentialStore`. See
  [The credential store](accounts.md#the-credential-store).

## Answer a proof request

The following Rust function opens the account, binds its storage, and answers a
proof request. The Swift, Kotlin, and browser APIs take the same steps with the
same names in their own casing.

```rust
use std::sync::Arc;

use walletkit::authenticator::artifacts::embedded::EmbeddedZkArtifacts;
use walletkit::requests::ProofRequest;
use walletkit::storage::CredentialStore;
use walletkit::{Authenticator, CredentialFilter, Environment};

async fn prove(
    seed: Vec<u8>,
    store: Arc<CredentialStore>,
    request_json: &str,
    now: u64,
) -> Result<String, Box<dyn std::error::Error>> {
    let authenticator = Authenticator::init_with_defaults(
        seed,
        None, // rpc_url: use the default.
        &Environment::Staging,
        None, // region: use the default.
        Arc::new(EmbeddedZkArtifacts::new()),
        store,
    )
    .await?;
    authenticator.init_storage(now)?;

    let request = ProofRequest::from_json(request_json)?;
    let response = authenticator
        .generate_proof(&request, &CredentialFilter::new(), Some(now))
        .await?;
    Ok(response.to_json()?)
}
```

In this function, `now` is the current time in Unix seconds. Send the JSON that it
returns back to the relying party.

On iOS and Android, use `CachingZkArtifacts` instead of `EmbeddedZkArtifacts` when
the keys are compressed, so that WalletKit decompresses them only once.

## Choose which credentials to prove

A proof request can accept several sets of credentials, for example "a passport
or an Orb credential". `CredentialFilter::new()` proves the first set the user
holds, in the relying party's order. When the app has to act on the credentials
before proving, it selects them first and then proves exactly that selection:

1. Build a `CredentialFilter`:
   - `excluding_credential_ids` never uses the given credentials.
   - `requiring_any_of` accepts only sets that contain at least one of the given
     credentials. WalletKit then uses the first such set in the relying party's
     order.
2. Call `CredentialStore::select_credentials`. It is read-only: it contacts no
   service and records nothing.
3. Act on the selection.
4. Prove it by passing its credential IDs to `CredentialFilter::pinned_to`. If the
   pinned credentials no longer answer the request, for example because one
   expired, `generate_proof` fails with `UnfulfillableRequest` instead of proving
   a different set.

For example, to compare the user's face against a credential that the proof
presents, require a credential whose face data is on the device:

```swift
let faceMatchable = Set(
    try store.listCredentials(issuerSchemaId: nil, now: now)
        .filter { !$0.isExpired && hasFaceData(issuerSchemaId: $0.issuerSchemaId) }
        .map(\.credentialId)
)
let selection = try store.selectCredentials(
    request: request,
    filter: CredentialFilter().requiringAnyOf(credentialIds: faceMatchable),
    now: now
)
let target = selection.first { faceMatchable.contains($0.credentialId) }!
try await compareFace(against: target)

let response = try await authenticator.generateProof(
    proofRequest: request,
    filter: CredentialFilter().pinnedTo(credentialIds: Set(selection.map(\.credentialId))),
    now: now
)
```

```kotlin
val faceMatchable = store.listCredentials(issuerSchemaId = null, now = now)
    .filter { !it.isExpired && hasFaceData(it.issuerSchemaId) }
    .map { it.credentialId }
    .toSet()
val selection = store.selectCredentials(
    request,
    CredentialFilter().requiringAnyOf(credentialIds = faceMatchable),
    now,
)
val target = selection.first { it.credentialId in faceMatchable }
compareFace(target)

val response = authenticator.generateProof(
    proofRequest = request,
    filter = CredentialFilter().pinnedTo(selection.map { it.credentialId }.toSet()),
    now = now,
)
```

`requiring_any_of` checks the whole set, so a request such as
`all(orb, any(device, passport))` keeps `device` when `orb` is the credential with
face data.

## Legacy World ID 3.0 proofs

The `v3` feature adds the World ID 3.0 API in the `v3` module. The Swift and
Kotlin packages include it; the browser package doesn't. docs.rs builds the crate
without `v3`, so read its documentation in the
[`v3` module source](https://github.com/worldcoin/walletkit/tree/main/crates/walletkit-core/src/v3)
or with `cargo doc --features v3`.
