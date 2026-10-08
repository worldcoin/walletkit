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
use walletkit::{Authenticator, Environment};

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
    let response = authenticator.generate_proof(&request, Some(now)).await?;
    Ok(response.to_json()?)
}
```

In this function, `now` is the current time in Unix seconds. Send the JSON that it
returns back to the relying party.

On iOS and Android, use `CachingZkArtifacts` instead of `EmbeddedZkArtifacts` when
the keys are compressed, so that WalletKit decompresses them only once.

## Legacy World ID 3.0 proofs

The `v3` feature adds the World ID 3.0 API in the `v3` module. The Swift and
Kotlin packages include it; the browser package doesn't. docs.rs builds the crate
without `v3`, so read its documentation in the
[`v3` module source](https://github.com/worldcoin/walletkit/tree/main/crates/walletkit-core/src/v3)
or with `cargo doc --features v3`.
