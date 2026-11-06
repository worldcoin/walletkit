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

## World ID key proofs for sign-in

`create_world_id_key_proof(seed, challenge, expected_issuer)` signs an Auth bridge
challenge without an `Authenticator`, credentials, or on-chain registration. Pass
the same 32-byte World ID seed used to initialize WalletKit. In World ID App,
Oxide derives it from the restored root with `worldIdV4Key()`.

Obtain user approval first. Read `expected_issuer` from trusted app configuration,
and pass the exact decoded JSON bytes of `key_proof_request.challenge`; do not
reserialize them. The function validates the challenge format, trusted issuer,
and supplied expiry. WalletKit rejects a challenge when its expiry is more than
30 seconds behind the device clock, allowing for clock skew without assuming a
maximum challenge lifetime. The IdP still enforces the exact deadline using its
server clock. The trusted issuer must be an HTTPS origin
without a path or trailing slash; HTTP is allowed only for loopback IP origins.

The result fields are `public_key` and `signature` in Rust, and `publicKey` and
`signature` in Swift/Kotlin. Send them as `public_key` and `signature` in the
encrypted bridge response with `credential_type: "key"`. See the
[IdP bridge contract](https://github.com/worldcoin/temporal-apps/blob/main/apps/idpapi/README.md#world-id-key-proof).

The sign-in key is derived with HKDF-SHA-256: the salt is
`WORLD-ID/IDP/SIGN-IN-KEY/V1\0`, the input key material is the World ID seed, and
the info is a four-byte big-endian counter starting at zero. Expand 32 bytes and
use the first valid P-256 secret scalar, trying at most 256 counter values.
The signature is low-S DER ECDSA over
`SHA256("WORLD-ID/IDP/KEY-PROOF/V1\0" || challenge_bytes)`. The compressed SEC1
public key and signature use unpadded base64url.

Devices restored from the same seed share this sign-in key. Revoking it disables
this sign-in method on all of them. This proof establishes key possession; it
does not certify World ID registration, use of an official app, human
verification, or a unique device. IdP apps must accept unverified accounts to use
it without another proof satisfying their verification requirements.

## Legacy World ID 3.0 proofs

The `v3` feature adds the World ID 3.0 API in the `v3` module. The Swift and
Kotlin packages include it; the browser package doesn't. docs.rs builds the crate
without `v3`, so read its documentation in the
[`v3` module source](https://github.com/worldcoin/walletkit/tree/main/crates/walletkit-core/src/v3)
or with `cargo doc --features v3`.
