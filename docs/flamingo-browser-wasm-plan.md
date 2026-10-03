# Flamingo browser WASM implementation plan

Status: proposal only; no runtime behavior changes. Reviewed October 2, 2026.

## Goal and boundary

Let `walletkit-web` callers submit supported face-match inputs through a browser
WebSocket, with enclave attestation verification, input encryption, response
decryption, and signed-result/input-binding verification inside Rust/WASM.
The browser page owns camera capture; the package worker owns the exchange.

This does not implement cold Selfie Check enrollment. Current Flamingo operations
are DeepFace and GrayBadge, both requiring a challenge image. A match result is
not an enrollment embedding, AMPC shares, a PCP, an issued credential, or proof of
camera provenance. Do not feed the same image into both roles to simulate enrollment.

Source snapshots:

- WalletKit main: `156ebee` (v0.26.0).
- Flamingo main: `c967f36518102aace1c6317455dccb11fddaa06f` (workspace v0.8.0).
- Proposed browser facade: WalletKit #584 at `f65afb2ae1fb47fb579c0427d714a17a0baefe88`.

## Existing work and overlap

See the [closed-PR reuse audit](flamingo-browser-reuse-audit.md) for each old
PR's actual scope, exact source revisions, file-level reuse decisions, and the
remaining implementation diff. Prefer selective ports over whole-file replacement.

| PR                                                                                                                         | State at review     | Decision                                                                                                                                                                                          |
| -------------------------------------------------------------------------------------------------------------------------- | ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [WalletKit #508](https://github.com/worldcoin/walletkit/pull/508), [#562](https://github.com/worldcoin/walletkit/pull/562) | Merged              | Reuse native matching and current WebSocket semantics.                                                                                                                                            |
| [WalletKit #548](https://github.com/worldcoin/walletkit/pull/548)                                                          | Closed, unmerged    | Earlier browser implementation; not an active dependency.                                                                                                                                         |
| [WalletKit #554](https://github.com/worldcoin/walletkit/pull/554)                                                          | Closed, unmerged    | Reuse target-gating ideas only; old HTTP dependency pins and UniFFI-only exports are insufficient.                                                                                                |
| [WalletKit #567](https://github.com/worldcoin/walletkit/pull/567)                                                          | Closed, unmerged    | Validation-only work; does not establish a channel.                                                                                                                                               |
| [Flamingo #116](https://github.com/worldcoin/flamingo/pull/116)                                                            | Closed, unmerged    | Superseded HTTP transport; do not restore it.                                                                                                                                                     |
| [Flamingo #129](https://github.com/worldcoin/flamingo/pull/129)                                                            | Closed, unmerged    | Rebase the browser transport onto current main; closure explicitly cites different browser authentication requirements. Its diff includes its old base stack: do not cherry-pick the entire diff. |
| [Pontifex #47](https://github.com/worldcoin/pontifex/pull/47)                                                              | Merged              | Browser clock/randomness groundwork exists. Verify the resolved dependency/features at runtime; no duplicate portability PR without a demonstrated gap.                                           |
| [WalletKit #584](https://github.com/worldcoin/walletkit/pull/584)                                                          | Open; based on #526 | Preferred binding integration point: dedicated wasm-bindgen facade. Wait for/rebase onto this stack instead of rebuilding the retired ubrn approach.                                              |
| [WalletKit #580](https://github.com/worldcoin/walletkit/pull/580)                                                          | Open                | Binding/toolchain overlap; coordinate with #584, no second toolchain migration here.                                                                                                              |
| [WalletKit #579](https://github.com/worldcoin/walletkit/pull/579)                                                          | Open                | Native attested-request signing. Preserve native behavior; its hardware callbacks/custom handshake headers are not browser authentication.                                                        |
| [Flamingo #128](https://github.com/worldcoin/flamingo/pull/128)                                                            | Open                | PAD-agnostic capture proposal may change input types. Target current released types, then adapt explicitly if this lands.                                                                         |
| [Flamingo #115](https://github.com/worldcoin/flamingo/pull/115)                                                            | Open                | Single-client-crate packaging may change imports/dependency declarations.                                                                                                                         |
| [Flamingo #71](https://github.com/worldcoin/flamingo/pull/71)                                                              | Open                | Single-image embedding extraction, but on the old `deepface/` HTTP layout. Separate enrollment follow-up, not a dependency of browser matching.                                                   |

No open PR found completes browser Flamingo matching end to end. State and heads
must be checked again when implementation starts.

## Exact surface to compile on WASM

Keep cryptographic operations in existing Rust implementations. Making a function
available internally on WASM does not require exporting it individually to JS.

| Layer                       | Functions/types                                                                                                                                                                        | Required treatment                                                                                                                           |
| --------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| WalletKit configuration     | `FlamingoMatcher::new`, `with_measurements`                                                                                                                                            | Compile on WASM; require HTTPS outside loopback development. Keep existing measurement validation.                                           |
| Development configuration   | `dangerously_skip_measurements`                                                                                                                                                        | Explicit development-only option, never automatic fallback after attestation failure. Preserve chain/signature/freshness/key-binding checks. |
| WalletKit matching          | `FlamingoMatcher::perform_match`, `client`, internal `perform_match`, `SessionClient::{connect, request_match}`                                                                        | Compile with browser-compatible futures; retain one reassignment maximum and shared verification path.                                       |
| Input validation/conversion | `FlamingoMatchRequest::{validate, into_inputs}`, `validate_bytes`, `From<FlamingoLiveCapture>`                                                                                         | Compile on WASM, preserve byte budgets, finite thresholds, operation/capture variants and typed errors.                                      |
| Outputs                     | `FlamingoMatchOutcome`, `FlamingoMatchRejection`, `FlamingoError`, `FlamingoDebugReport`, `VerifiedMatchToken::{match_coefficient, as_bytes, signing_key_attestation}` and conversions | Compile on WASM; serialize a bounded result only after verification. Preserve diagnostic status separately from authenticated claims.        |
| Flamingo client             | `Config` validation, `FlamingoVerifierClient::{new, connect}`, `FlamingoVerifierSession::request_match`                                                                                | Browser implementation of connection/timers; same verified assignment and sealed result semantics.                                           |
| Verification/channel        | Assignment verification, Pontifex verifier/channel operations, CBOR encode/decode, signing-key attestation and token/input checks                                                      | Reuse internally; do not expose arbitrary encrypt/decrypt or unchecked public-key setters to JS.                                             |
| Native auth                 | `with_headers`, `build_request`, `connect_with`; #579 `new_attested`/signer integration if merged                                                                                      | Keep native-only where arbitrary upgrade headers or hardware callbacks are required. Never silently ignore configured auth on WASM.          |

### Proposed public TypeScript API

Add one operation to the existing initialized `WalletKit` client:

```ts
performFlamingoMatch(
  config: FlamingoConfig,
  request: FlamingoMatchRequest,
  options?: { signal?: AbortSignal },
): Promise<FlamingoMatchOutcome>
```

No separate public `connect`, `encrypt`, or session-handle API is needed for the
first usable implementation. The operation validates inputs, connects, verifies
the assignment, seals and sends the images, and verifies the result. Opening a
connection before camera capture would consume the server's assignment idle
budget. Add preconnection only if a measured UX need justifies its lifecycle.

Data contract:

- `FlamingoConfig`: `hostUrl`, a discriminated attestation policy of pinned
  measurements or explicit development bypass, and a bounded overall
  `timeoutMs` (default 60,000; accepted range 1–120,000). Do not export arbitrary
  HTTP headers. Browser authorization is the gate described below.
- Pinned policy uses `measurements: Record<number, Uint8Array>` with the same
  PCR0/1/2 requirements as WalletKit's native wrapper. Do not weaken that policy
  to match the underlying client's less restrictive minimum.
- `FlamingoMatchRequest`: discriminated `deepFace` or `grayBadge`, with
  `live`, `rtmsChallenge`, finite `matchThreshold`; DeepFace additionally has
  `orbCredential` and exact original `hashesJson` bytes.
- `live`: `vanilla` with `image`, or `lightGuard` with `illuminated`,
  `unilluminated`, and `matchingFrame`. All image/hash buffers are `Uint8Array`.
- Matched result: encoded token and signing-key attestation **together**, plus
  `matchCoefficient` and bounded diagnostic status. Preserve the native opaque
  token API; the web facade can copy its read-only bytes into plain data.
- Rejected result: structured rejection and diagnostic status. Transport,
  attestation, malformed response and timeout errors reject the promise; they
  are not biometric rejection outcomes. Unsigned rejection diagnostics are not
  signed claims.
- Preserve typed error fields (`code`, bounded operation/stage, retry hint,
  input field/limit where applicable) across the worker boundary. Do not serialize
  raw upstream bodies, image data, authentication material, or debug formatting.
- Returned JS bytes are not a portable assertion that verification happened:
  downstream proof/verifier consumers must verify or use a Rust-held verified
  object. This PR does not add a JS-to-`VerifiedMatchToken` constructor or claim
  that existing `generateProof` consumes a Flamingo result.

## Atomic implementation units

### 1. Resolve browser admission (service/config decision)

Identify a supported gateway route and browser authentication mechanism before
claiming live usability. A browser WebSocket cannot reproduce native arbitrary
`Authorization`/integrity upgrade headers. Do not put durable credentials in a
URL, expose native app tokens, or fall back to an unauthenticated route.

Evaluate an existing same-origin authenticated gateway/tunnel first, keeping
attestation verification and encryption in the browser. A tunnel must relay only
ciphertext after the verified assignment; uploading plaintext to a native helper
would change the trust boundary. If cookies are chosen, specify Origin checks,
SameSite/third-party-cookie behavior, expiry, and admission limits. If service
changes are required, review them separately; this plan does not invent a new
authentication protocol.

The checked-in staging host is `flamingo-verifier-stage.worldcoin.dev`. This
investigation received Cloudflare HTTP 403 on `/ready` and failed a WebSocket
assignment probe. No image was sent; the rejecting rule has not been identified.
The deployment repo documents debug enclaves in preproduction, requiring an
explicit measurement bypass. A debug smoke test cannot satisfy the measured
enclave acceptance test.

Done when: an authenticated browser handshake works from the intended origin,
the deployment/client protocol versions are known, and the trusted measurement
policy (or explicitly labeled development mode) is supplied out of band.

### 2. Flamingo: browser transport and cancellation

Files: workspace `Cargo.toml`/`Cargo.lock`; `verifier/client/Cargo.toml`;
`verifier/client/src/{client,session,lib,error}.rs`; a browser session module;
browser tests; `.github/workflows/rust-ci.yml`; `docs/api.md`.

- Adapt #129's target split to the current v0.8 protocol. Keep native
  Tokio/tungstenite/TLS dependencies out of browser targets. Enable compatible
  browser randomness, clocks and timers through the resolved dependency graph.
- Share assignment verification, encoding/sealing and result verification;
  keep only I/O and timing target-specific. Browser session cleanup closes its
  socket when canceled/dropped and unregisters callbacks.
- Retain the same socket for assignment and match. Bound frames before parsing,
  reject unexpected frame types/order, enforce the current channel domain and
  padding contract, and preserve input/result binding.
- Bound connection and each phase by the remaining overall deadline. A retry
  gets only the remaining budget. Do not add retries for arbitrary transport or
  integrity failures.
- Prove browser compatibility of resolved Pontifex 3.x clock/randomness paths;
  #47's merge alone is not proof that the chosen feature graph works.

Done when: browser runtime tests exercise the real client verification/sealing
path, native tests still pass, and a compatible version/revision is available.
Prefer a published version; temporary Git dependencies must be exact revisions
and pass repository dependency policy. Do not pin the old HTTP branch.

### 3. WalletKit core: enable the existing implementation

Files: `Cargo.toml`, `Cargo.lock`, `crates/walletkit-core/Cargo.toml`,
`crates/walletkit-core/src/lib.rs`, `flamingo/{mod,types,errors}.rs`;
`deny.toml` only if exact Git dependencies require it.

- Move the required Flamingo crates and `async-trait` out of native-only
  dependencies, then remove the module-level WASM exclusion.
- Split only native header/signing configuration and transport calls by target.
  Use `async_trait(?Send)` and compatible associated-type bounds on WASM; retain
  `Send`/`Sync` contracts on native. Adapt async UniFFI exports to the browser
  binding stack selected by #584 rather than forcing a Tokio runtime on WASM.
- Ensure `OnceCell` initialization and retry control do not require a native
  executor. Keep validation before network activity and bounded reassignment.
- Preserve new #579 native authentication semantics when rebasing; never make
  its callback signer a mandatory browser dependency.
- Keep pure validation/serialization tests portable; gate TCP-only fixtures,
  not all tests, to native targets.

Done when: core compiles on WASM and native, with the same semantic validation,
verification and typed failure behavior. This alone is not a callable npm API.

### 4. WalletKit browser facade and worker

Base this unit on #584 once its binding direction is settled. Files:
`crates/walletkit-web/{Cargo.toml,src/lib.rs,src/error.rs}` plus a focused
`src/flamingo.rs`; `web/walletkit/src/{protocol,index,walletkit.worker}.ts`.

- Parse the JS config/input shape in Rust, checking buffer sizes/types before
  expensive copies where possible; call the existing core matcher. Do not
  duplicate attestation/channel crypto or biometric policy in TypeScript.
- Export the one high-level operation from the facade and package worker.
  Extend structured-clone request/result/error types exhaustively.
- Copy caller buffers into owned request buffers (do not detach caller-owned
  memory); transfer those owned buffers to the worker. Clear owned JS/Rust
  buffers on completion/cancellation where feasible, without claiming complete
  erasure of browser internal copies. Never persist capture inputs.
- Reject a second pending Flamingo operation as busy before copying its images;
  do not accumulate an unbounded biometric queue. Preserve serialization of
  existing wallet mutations.
- Use an out-of-band cancel control message keyed by RPC request ID. The current
  worker serializes all messages: queuing cancel behind the active match would
  make it ineffective. Register cancellation before enqueueing a match, handle
  abort-before-start, and cancel/drop the Rust future so the socket closes.
- An `AbortSignal` stays on the page; send only cancellation IDs across workers.
  Settle each call once, remove listeners, discard late results, and release
  cancellation entries after completion. Cancellation does not kill the wallet
  worker or lose the unlocked account. Existing `terminate()` remains the hard
  stop. `close()` cancels pending matches before draining normal wallet work.
- Include queue wait in the deadline; do not start network work after expiry.
  Keep debug reports opt-in for application use and out of automatic logs.

Done when: the npm API runs the full exchange in its existing worker and abort,
close, timeout, malformed input and worker crash all settle callers predictably.

### 5. Regression tests, CI and documentation

Files: existing `web/walletkit/tests/browser.spec.ts`/fixtures, browser package
README, core Flamingo tests, `.github/workflows/ci.yml`; upstream Flamingo tests
from unit 2. Reuse existing frameworks and test-only build hooks.

Required checks:

1. Input parsing: both operations/capture variants; empty/oversized/trailing
   data, incorrect typed arrays, NaN/out-of-range threshold, malformed pins.
2. Assignment: invalid chain/signature, stale attestation, wrong PCRs or
   public-key binding fail **before any image frame is sent**.
3. Result: verify success, reject modified signature/signing-key attestation,
   wrong operation/capture/challenge binding, malformed/oversized frames;
   preserve unsigned rejection and diagnostic omission separately.
4. Lifecycle: abort queued/connecting/waiting-for-result; timeout, socket close,
   worker failure, duplicate/late response; next operation works after abort;
   closing releases network resources and storage; second match is busy.
5. Retry: exactly one explicit reassignment with a fresh verified assignment,
   no retry after cancellation or exhausted deadline, no auth fallback.
6. Real-browser test through the published worker entry point, not just a Rust
   compile check or a mocked `performFlamingoMatch` method. Test-only trust
   fixtures must never enter release builds. Use a controlled signed fixture
   for reproducible verification tests plus a separate live attested smoke test.
7. Native regression checks for match errors, custom headers, and #579 signing
   if merged. Required Rust formatting, Clippy, dependency checks, package
   typechecking/formatting and WASM browser tests. Use the repository Nix WASM
   devshell. Do not run Xcode builds; native iOS validation is user-run.

Document HTTPS/CSP `connect-src`, browser gateway admission, input ownership,
abort/deadline behavior, debug mode, and which tests used fixtures versus a live
measured enclave. Do not add camera/model/PCP functionality to WalletKit here.

## Ordering and merge criteria

Units 1 and 2 define a usable upstream dependency. Unit 3 depends on unit 2.
Unit 4 depends on unit 3 and the #584 browser stack. Unit 5 accompanies each code
unit, with final package/runtime validation after unit 4. Keep the runtime work
in separate reviewable PRs; this planning PR can merge independently.

Do not mark the browser implementation ready based solely on WASM compilation.
Require browser verification/lifecycle tests and an accepted browser admission
path. Record live measured-enclave testing separately from debug-enclave testing.
Normal package rollback is sufficient; no database/schema changes are planned.

Enrollment remains a subsequent service effort: update or supersede Flamingo
#71 for the current protocol, define the accepted embedding/share/custody output
and issuer evidence contract, then add its operation to the browser surface.
