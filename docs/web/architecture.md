# How the browser package works

This page explains how `@worldcoin/walletkit-web` runs WalletKit in a browser. It
is for contributors to the package. To use the package, see
[Use WalletKit in the browser](package.md).

## Components

The package has four layers. Each layer talks only to the one next to it.

```mermaid
flowchart LR
  app[App code] --> proxy["Page proxy<br/>web/walletkit/src/index.ts, remote.ts"]
  proxy -- postMessage --> worker["Worker<br/>web/walletkit/src/walletkit.worker.ts"]
  worker --> facade["walletkit-web crate<br/>crates/walletkit-web"]
  facade --> core["walletkit-core"]
```

In order from the app down:

1. **Page proxy.** `initializeWalletKit` starts the worker and returns a typed
   proxy. The proxy turns every property access into a request to the worker and
   returns a `Promise`. Method signatures come from the declarations that
   `wasm-bindgen` generates. Only the public type names are listed by hand, in
   `remote.ts` and `index.ts`.
1. **Worker.** The worker loads the WASM module, installs persistent storage, and
   runs requests. It keeps every Rust object and gives the page an opaque handle
   for each one.
1. **`walletkit-web` crate.** A `wasm-bindgen` facade over `walletkit-core`, with
   one wrapper class for each UniFFI object that the browser supports. Wrappers
   keep the names and arguments of the Swift and Kotlin bindings, in `camelCase`.
1. **`walletkit-core`.** The same Rust code that the Swift and Kotlin bindings use,
   built for `wasm32-unknown-unknown`.

The browser package doesn't use UniFFI. The facade exports only the surface that a
browser can serve: it has no foreign traits or callbacks.

## Requests and objects

[`protocol.ts`](https://github.com/worldcoin/walletkit/blob/main/web/walletkit/src/protocol.ts) defines the messages between
the page and the worker. A call names its target in one of three ways: a
module-level function, a static function of a class, or a method of an object
handle.

Rust objects can't cross `postMessage`, so the worker keeps them in a handle table.
When a call returns a Rust object, the worker stores it and returns `{ $ref:
handle }`, and the page wraps the handle in a proxy. When the page passes a proxy
as an argument, the page sends its handle, and the worker swaps it back for the
object. Every other value crosses as structured-clone data.

An object stays in the worker until one of the following happens:

- The app calls `free()` on the proxy.
- The proxy is garbage collected. A `FinalizationRegistry` then releases it.
- The app closes the instance. `close()` frees every remaining object.

A proxy belongs to the instance that created it. A call that passes it to another
instance rejects with a `TypeError`, because its handle could name an unrelated
object there.

The worker dispatches only functions and methods that the WASM module exports. It
rejects `wasm-bindgen` internals, names that start with `_`, and the module setup
functions that only the worker calls. As a result, an export added to the
`walletkit-web` crate is callable from the page with no change to the worker.

## Ordering

The worker runs one request at a time, including the awaited part of asynchronous
calls. Rust state shared between objects, such as a credential store that an
authenticator also uses, therefore never sees interleaved operations.

The cost is head-of-line blocking: a call that never settles blocks every call
queued behind it. `close()` sends its request through the same queue and, after
`CLOSE_TIMEOUT_MS` in [`index.ts`](https://github.com/worldcoin/walletkit/blob/main/web/walletkit/src/index.ts), terminates the
worker.

## Byte arrays and secrets

Seeds and database keys cross the worker boundary as `Uint8Array`s. The page copies
each array and transfers the copy's buffer, so the page heap keeps no second copy.
The caller's own array is left unchanged. If encoding fails before the message is
posted, the page clears the copies itself.

`wasm-bindgen` copies byte arguments into Rust memory when the export is invoked,
so the worker clears its copies right after the invocation returns, without
waiting for an asynchronous call to settle. In Rust, the database key lives in
zeroizing memory until its last owner releases it.

## Errors and crashes

The facade converts a Rust error into a JavaScript `Error`. The error's `name` is
the error type, its `code` is the variant, and its `detail` holds the variant's
fields; the worker appends `detail` to the message before sending it to the page.
Every message and detail passes through `sanitize_hex_secrets`. Argument
validation throws a `TypeError`.

A Rust panic traps the WASM module and leaves its memory in an unknown state. The
worker detects the resulting `WebAssembly.RuntimeError`, marks itself crashed, and
flags the error response as fatal. The page client, the `WorkerClient` class in
`index.ts` that owns the worker and its pending requests, then stops: it rejects
pending and later calls, and `isStopped()` returns `true`. A worker `error` or
`messageerror` event stops the client the same way.

The workspace release profile sets `panic = "abort"`, so a panic on iOS or Android
ends the app process. Code shared with those platforms must return errors instead
of panicking.

## Storage

The worker installs persistent storage during initialization, before any database
opens. The storage design has these parts:

- **VFS.** WalletKit stores its SQLite databases in OPFS through the
  sync-access-handle (SAH) pool VFS from `sqlite-wasm-vfs`. SQLite3MC wraps that
  VFS as `multipleciphers-opfs-sahpool`, and connections open only through the
  encrypted wrapper, so persistence never bypasses encryption. See
  [`opfs.rs`](https://github.com/worldcoin/walletkit/blob/main/crates/walletkit-sqlite/src/opfs.rs).
- **Synchronous access.** Installing the pool is asynchronous, but SQLite calls
  after that are synchronous. The pool therefore reserves its capacity at install
  time, because synchronous SQL can't grow it.
- **Single owner.** The pool holds its OPFS handles until the worker terminates, so
  one worker per origin owns the storage. Closing a connection doesn't release
  them. A second worker fails to install the pool, even for a different root path.
- **Retries.** A worker that just terminated releases its handles asynchronously.
  When another context still holds the pool, initialization retries with jittered
  backoff, following `POOL_RETRY_DELAYS_MS` in
  [`walletkit.worker.ts`](https://github.com/worldcoin/walletkit/blob/main/web/walletkit/src/walletkit.worker.ts), and then
  reports the error. It reports other installation failures immediately.
- **Journal mode.** On WASM, databases use the rollback journal (`DELETE`) instead
  of WAL, because the SAH pool doesn't provide WAL's shared-memory methods. The
  encrypted database format is the same as on iOS and Android.
- **Keys.** The browser has no device keystore, so the host supplies the database
  key through `StorageKeys.fromBytes`. No key envelope is written, so there is no
  envelope to delete in `destroyStorage()`.

## Proposed selfie challenge calls (draft)

This is an API proposal, not an exported API. Implementation depends on
[biometrics-tee #91](https://github.com/worldcoin/biometrics-tee/pull/91) for pose
definitions and generation, and
[WalletKit #604](https://github.com/worldcoin/walletkit/pull/604) for the browser
enrollment client integration. **Merging #91 alone does not enable these calls:**
it adds generation helpers, without a challenge RPC, run registry or evaluator.

### Two service calls

Both functions would be available on the existing `WalletKit` instance. These
TypeScript declarations describe the proposed interface; the eventual Rust
facade owns the exports and generates their declarations.

```ts
type SelfieChallengeOption = 0x00 | 0x01 | 0x02;

type SelfieChallengeStep = {
  challengeId: string;
  stepIndex: number;
  targetResponse: SelfieChallengeOption;
  expiresAtUnixMs: number;
};

type SelfieChallengeUpdate =
  | { status: "next" | "retry"; step: SelfieChallengeStep }
  | { status: "completed"; challengeId: string; result: Uint8Array }
  | { status: "failed"; challengeId: string; reason: string };

declare function prepareSelfieChallenge(
  configJson: string,
  requestBinding: Uint8Array,
): Promise<SelfieChallengeStep>;

declare function submitSelfieChallengeEvidence(
  challengeId: string,
  stepIndex: number,
  evidence: Uint8Array,
): Promise<SelfieChallengeUpdate>;
```

The pose codes match #91's `TargetResponse`: forward `0x00`, anatomical left
`0x01`, right `0x02`. `stepIndex` starts at zero. The enclave keeps the full
three-pose sequence; the page receives only the current instruction.

`configJson` is the trusted endpoint and enclave measurement policy, following
#604. `requestBinding` identifies the intended authentication request and
recipient. Its canonical encoding must be agreed with the TEE and final verifier;
the verifier must check it against its own pending request. A caller-supplied
binding or public challenge ID does not establish ownership.

`evidence` is a direct byte argument so it follows the existing worker transfer
and clearing path. Its bounded encoding must come from the TEE evaluator's
protocol: a still image can show a pose, while movement and hold checks need
temporal evidence. Do not freeze a JPEG-only format before that decision. The
terminal `result` is the encoded authenticated TEE outcome; its format and the
typed rejection reasons also depend on that protocol.

### From Start to completion

```mermaid
sequenceDiagram
  participant App as Web authenticator
  participant WK as WalletKit worker
  participant TEE as Biometrics TEE
  App->>WK: prepareSelfieChallenge(configJson, requestBinding)
  WK->>TEE: Verify assignment, then start the run
  TEE-->>WK: Challenge ID, private run credential, first instruction
  WK-->>App: First instruction
  loop Each requested step
    App->>App: Estimate pose and automatically capture evidence
    App->>WK: submitSelfieChallengeEvidence(id, stepIndex, evidence)
    WK->>TEE: Submit evidence with the retained run credential
    TEE->>TEE: Check run, evaluate evidence, update state
    TEE-->>WK: Next instruction, retry or terminal outcome
    WK-->>App: Public update
  end
```

`prepareSelfieChallenge` resolves after receiving the first instruction. It must
not wait for camera input or completion: the worker awaits each call before
dispatching the next one. Camera access, pose estimation and evidence capture
belong to the web authenticator and run between WalletKit calls.

WalletKit privately retains the connection and run credential, with one active
challenge per instance initially. A second prepare call rejects while that run
is active. Reuse the existing instance; another worker competes for the origin's
OPFS ownership. The enclave generates and erases the seed; the run credential
stays in the worker. Neither is returned to the page, persisted or logged.

The TEE obtains the expected pose from its own run state, checks ownership,
expiry and step order, and evaluates submitted media. Only its decision can
advance the step or complete the run. A browser's pose estimate, timestamp or
`challenge_completed` flag cannot establish completion. `retry` requests new
evidence for the same step; `next` advances to the returned instruction. Invalid
arguments, policy/attestation failures and transport failures reject the promise.

Terminal outcomes and expiry release the worker's session and private state.
For v0, a disconnect or ambiguous submission timeout invalidates the local run:
close the connection and start a fresh attempt, without reconnecting or replaying
the submission. The enclave must bound and expire abandoned runs. Existing
`terminate()` cancels immediately by stopping the entire WalletKit instance;
`close()` is queued and has a termination deadline. Abandoning a still-active run
therefore requires waiting for expiry or stopping the whole instance. This
proposal adds no separate cancel, seed-generation, sequence-decoding or
completion service call.

### Upstream work and implementation boundary

Before these exports can ship, biometrics-tee needs:

- A bounded enclave run registry, ownership checks, expiry and atomic step
  transitions, plus start and evidence-submission RPCs.
- A persistent client/host exchange that keeps the run on its owning enclave.
  The existing extraction session is consumed after one request and closes its
  socket; opening a new extraction connection for each step cannot preserve an
  in-memory run across replicas.
- An evidence format, size/frame limits, evaluation policy and response types.
  Embedding extraction alone does not evaluate the challenge.
- Response authentication and replay handling. The current encrypted channel
  does not attest its replies or provide request replay protection. A verifier
  accepting a relayed terminal outcome must authenticate it and check its request
  binding, freshness and single use.

The WalletKit implementation would add a small `challenge.rs` Rust facade under
`crates/walletkit-web/src`, register it in `lib.rs`, and export the generated
record/option types from `web/walletkit/src/index.ts`. Its two functions delegate
to the shared enrollment client; generation and evaluation stay in the enclave.
The page/worker dispatcher needs no new service methods. Add consumer type checks
for the exported types and browser checks for lifecycle, rejected submissions and
cleanup when that implementation is available. This proposal changes no runtime
exports, dependency pins or existing extraction behavior.

## Build output

`bun run build` in `web/walletkit` produces the published `dist` directory:

1. `cargo build` compiles the `walletkit-web` crate for `wasm32-unknown-unknown` in
   release mode.
1. The `wasm-bindgen` CLI generates the JavaScript glue and TypeScript declarations
   with `--target web`. The CLI version must match the `wasm-bindgen` crate in
   `Cargo.lock`; the build checks this.
1. Binaryen's `wasm-opt -Oz --converge` optimizes the module into
   `walletkit.wasm`.
1. esbuild bundles the page entry point and a self-contained worker, and the build
   copies the module and its declarations into `dist/generated`.

The module embeds the proving keys uncompressed (the `embed-zkeys` feature), which
is why it is about 40 MB and why the browser needs no `CachingZkArtifacts`.

For the build commands, see [Develop the browser package](development.md).
