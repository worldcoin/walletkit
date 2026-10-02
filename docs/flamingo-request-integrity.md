# Flamingo request integrity (draft)

`FlamingoMatcher::new` requires a `RequestIntegrityProvider` supplied by the host
app. The provider owns integrity-token acquisition and the corresponding hardware
signer. WalletKit owns the verifier connection and invokes the provider for each
new connection or reassignment.

**This draft uses a mock digest and opens no network connection.** It prepares
the session, invokes the signer, then returns
`FlamingoError::CanonicalSigningUnavailable` before opening a socket. No integrity
headers are sent. It has no dependency on the private `attested-request` crate;
wire the shared signing implementation before enabling proxy access.

## Callback contract

The native callbacks and session record are exported through UniFFI:

```text
RequestIntegrityProvider.prepare() async
    -> RequestIntegritySession

RequestIntegritySession {
    token: String
    platform: RequestIntegrityPlatform // Ios or Android
    signer: RequestDigestSigner
}

RequestDigestSigner.signDigest(clientDataHash: bytes)
    -> signature bytes
```

Both callbacks return `RequestIntegrityError` on failure. Do not include tokens,
key identifiers, platform error dumps or other sensitive values in error text.

`prepare()` may reuse a still-valid token or obtain a new one. It must return the
token and a signer pinned to the exact hardware key certified by that token as
one session. A key rotation must not change which key an already-returned signer
uses. WalletKit does not decode the token or know the AG audience, environment or
key ID.

`signDigest` receives exactly 32 bytes and returns the platform's signature
encoding unchanged: an App Attest assertion on iOS or a DER ECDSA signature on
Android. The synchronous signing callback runs on a blocking worker. Preparing
and signing share a 30-second timeout. A running native signing operation cannot
be forcibly cancelled; its late result is discarded. The private key stays in
App Attest or Android Keystore.

## Native adapter

The app implements these WalletKit interfaces with small Swift/Kotlin adapters
around its existing native integrity session. Oxide already uses that native
signer through its own foreign callback; WalletKit does not depend on Oxide or
share its generated callback types.

For each `prepare()` call, the adapter obtains a valid native session for the
Flamingo audience, then returns:

- The native session's token.
- The current platform.
- A WalletKit signer adapter capturing that native session's signer and audience.

On iOS, the signer adapter delegates to the existing session's
`signRequest(digest:rpId:)`, passing the session audience as `rpId`. On Android, it
delegates to the existing signer bound to the token's Keystore alias. Use the
session signer rather than the service used to mint tokens.

The app passes its adapter to the matcher, then configures approved enclave
measurements as before. In Rust, the provider is an `Arc<dyn
RequestIntegrityProvider>`; Swift/Kotlin callers pass their implementation of the
generated provider interface.

```text
matcher = FlamingoMatcher(
    hostUrl: directVerifierUrl,
    integrityProvider: appIntegrityProvider
).withMeasurements(approvedMeasurements)
```

`withHeaders` is for additional metadata. The `Integrity-Token`,
`Signature-Input` and `Signature` headers are reserved for WalletKit; callers
cannot override them.

## Completing canonical signing

Once `attested-request` is available, replace the mock at the signing boundary
with its canonical request construction and signature-header generation. Build
the digest from the final WebSocket handshake URI and the prepared token; a new
connection requires a fresh timestamp, nonce and signature even when the token
is reused.

Validate the resulting headers against shared vectors and real hardware on both
platforms before enabling the direct proxy endpoint. Request integrity admits
the WebSocket connection. Enclave measurement checks, attested-channel encryption
and match-token verification remain independent requirements.
