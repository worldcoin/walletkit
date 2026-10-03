# Closed browser PR reuse audit

Reviewed October 2, 2026 against the snapshots in the
[implementation plan](flamingo-browser-wasm-plan.md). This is a source/diff audit,
not a compile-tested transplant. Line counts describe historical changes, not
estimates for the final implementation.

## Recommendation

Port the browser transport from Flamingo #129, reuse small target-gating hunks
from WalletKit #554, and adapt relevant tests from #548/#567. Write the thin
current worker/facade integration against #584. Keep current main's cryptography,
typed errors, diagnostics, and native behavior.

No complete file reviewed is ready to copy unchanged and ship. The 240-line
`session_browser.rs` from #129 is suitable as a starting file, with the specific
changes below. Rewriting its exchange from scratch would discard useful work;
copying entire older WalletKit files would discard newer behavior.

## Historical scope and remaining diff

| Closed PR / reviewed head                                                    | What it actually changed                                                                                                                                                                                                                | Reuse                                                                                                                        | Changes still needed                                                                                                                                                                                                                                                                                               |
| ---------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| [WalletKit #548](https://github.com/worldcoin/walletkit/pull/548), `2a4b2b4` | 19 files: portable core gating/dependencies; new 232-line wasm-bindgen facade; standalone JS client/worker, build script and Playwright harness; CI/dependency policy.                                                                  | Config parsing, redacted-error approach, and test scenarios as references.                                                   | Replace its old flat three-image request and tuple outcomes with current DeepFace/GrayBadge, explicit capture variants, structured errors and diagnostics. Integrate into #584's existing facade/worker instead of creating the standalone `web/` package. Add per-operation abort/deadline and bounded admission. |
| [WalletKit #554](https://github.com/worldcoin/walletkit/pull/554), `775c67c` | 8 files: move dependencies to all targets; remove module WASM exclusion; `async_trait(?Send)`/UniFFI export gating; native-only tests; old Flamingo/Pontifex Git pins and lock/policy/CI changes. No handwritten npm methods.           | Small dependency-move and target-gating hunks.                                                                               | Apply to today's session-based matcher, including target-specific session bounds/header paths. Use compatible current client dependencies and #584's bindings. Do not restore old HTTP pins or disable portable tests wholesale.                                                                                   |
| [WalletKit #567](https://github.com/worldcoin/walletkit/pull/567), `571687f` | 6 files: split 973 lines out of `mod.rs` into native-only `matcher.rs`; move token/outcome code into native-only `verified.rs`; expose `validate_flamingo_match_request`; make input types/dependencies portable; add validation tests. | Threshold/empty/size-limit test cases where they add coverage. Optional validation helper only if the final facade needs it. | This split deliberately leaves matching unavailable on WASM. Full browser support needs matcher, verified results and client dependency portable. Current main already has richer validation tests; avoid duplicating them.                                                                                        |
| [Flamingo #116](https://github.com/worldcoin/flamingo/pull/116), `9fa201e`   | 8 files: browser HTTP Fetch handling, streamed response bounds, browser tests, Nix browser runner/CI and dependency changes; substantial `client.rs` rewrite.                                                                           | Browser-runner setup concepts and verification/limit test intent, checked against current tooling.                           | HTTP assignment/POST, Fetch cookie/cache policy and HTTP response streams do not implement today's two-frame WebSocket exchange. Port scenarios to WebSocket fixtures; keep current verifier implementation.                                                                                                       |
| [Flamingo #129](https://github.com/worldcoin/flamingo/pull/129), `7edfeea`   | Full PR includes the preceding HTTP-to-WebSocket migration. Its final commit alone adds the browser session and target split, randomness/timer dependencies, native test gating and a WASM compile CI job.                              | Best implementation seed: final commit and its new browser session file.                                                     | Add accepted browser admission, cancellation/cleanup guarantees, overall deadlines, text-frame bounds and real browser runtime coverage. Reconcile current TLS dependencies and protocol/result changes.                                                                                                           |

## Flamingo #129: isolate the useful commit

Use [commit `7edfeeaa26b3b42603daaa12b8eaefe9bd1e3e4a`](https://github.com/worldcoin/flamingo/commit/7edfeeaa26b3b42603daaa12b8eaefe9bd1e3e4a),
whose parent is `aba0310270771842e068985cb621243d3e500e06`.
It changes **9 files, +362/-7**, including **240 new lines** in
`verifier/client/src/session_browser.rs`. These counts exclude the preceding
host/API/e2e migration present in the PR's full diff.

| File in the isolated commit              | Treatment against current main                                                                                                                                     |
| ---------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `verifier/client/src/session_browser.rs` | Restore as a starting file, then adapt and test. It already uses current-style assignment, sealed binary exchange, shared verification helpers and browser timers. |
| `verifier/client/src/client.rs`          | Reapply dispatch and native-only `build_request`/`connect_with` hunks. Retain current verification and diagnostic result handling.                                 |
| `verifier/client/src/lib.rs`             | Reapply target-specific session selection/exports; scope lint allowances narrowly.                                                                                 |
| `verifier/client/src/error.rs`           | Add the browser transport variant alongside current error variants; map it through WalletKit without exposing raw URL/payload details.                             |
| `verifier/client/Cargo.toml`             | Reapply target dependency split; also account for current `rustls`/`webpki-roots`, which were not in that old split. Resolve actual randomness versions/features.  |
| `Cargo.lock`                             | Regenerate from chosen manifests; never copy the old lockfile wholesale.                                                                                           |
| `verifier/client/tests/ws.rs`            | Preserve native gating, and add actual browser tests separately. Native tests do not validate browser socket lifecycle.                                            |
| `.github/workflows/rust-ci.yml`          | Add browser checks to current CI/action pins; extend compile coverage to runtime tests.                                                                            |
| `docs/api.md`                            | Adapt browser limitations to the agreed admission mechanism; do not present cookie auth as implemented.                                                            |

Required adaptations inside the candidate browser session:

1. **Cancellation and closure:** it drops the stream on ordinary completion/error.
   It has no explicit application cancellation API. Verify the library's behavior
   when a connect future or session is dropped, including late connection success;
   add explicit cleanup where needed. Do not assume drop guarantees from inspection.
2. **One deadline:** it starts separate connection, assignment and match timers.
   Thread the remaining overall budget through those phases and reassignment.
3. **Inbound limits:** it checks binary result size, but its assignment/error text
   decoders do not check length before JSON parsing. Add bounded text handling.
   Browser WebSocket APIs deliver already-buffered messages; application checks
   cannot impose a native transport-level allocation limit. Document that boundary
   and enforce server/gateway message limits too.
4. **Current shared helpers:** it already calls `verify_assignment`,
   `open_verified_match` and `ensure_claims_match`. Keep those functions from
   current main so newer result diagnostics and verification behavior survive.
5. **Tests:** its two local tests cover URL mapping and malformed assignment text;
   its added CI job only checks compilation. Add browser verification, lifecycle,
   frame-bound, retry and deadline tests from the implementation plan.

No changes to host matching, enclave inference or protocol schemas are implied by
this transport port. Gateway admission may require separate service changes.

## WalletKit files: why whole-file replacement is unsuitable

- #548's facade calls the old `FlamingoMatchRequest` struct, sets
  `light_guard_image: None`, accepts custom headers, and recognizes the old small
  rejection set. Its opaque JS class results also differ from #584's plain
  structured-clone worker contract. Reuse the parsing/error ideas, not the file.
- #548's browser tests observe HTTP POSTs to `/v1/enclave-assignment`; those
  assertions must become WebSocket frame assertions. The useful invariant is
  still “invalid assignment sends no biometric frame.” Closing its separate
  worker is not the planned per-match abort that preserves the wallet session.
- #554's useful core changes are small hunks, not replacement files. Its
  `MatchClient` uses an `Assignment` associated type; today's implementation owns
  a socket-backed `Session`. `?Send` alone is not sufficient if native `Send`/`Sync`
  bounds remain on that browser session.
- Comparing #567's `matcher.rs` with current main's `flamingo/mod.rs` gives
  **+235/-57** (including module scaffolding). Current code adds structured errors,
  diagnostic-bearing outcomes and regression tests. Copying the old 973-line file
  would regress those changes while still leaving networking native-only.
- Keep current `types.rs`/`errors.rs` as the source of truth. A large movement-only
  split is unnecessary unless it makes the final target boundary clearer.

## Expected new work after reuse

| Area                       | Expected diff                                                                                                                                                                                                                |
| -------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Flamingo browser transport | Adapted #129 browser file, small target-dispatch/dependency edits, cleanup/deadline/limit improvements and browser tests.                                                                                                    |
| WalletKit core             | Small edits to existing matcher/types/error mapping and manifests; preserve current native API. No reimplementation of attestation or channel crypto.                                                                        |
| WalletKit web              | New focused facade adapter plus additions to existing `protocol.ts`, `index.ts`, and worker dispatcher. Cancellation control routing, owned image transfer, structured errors and admission limits are new integration work. |
| Tests/docs/CI              | Port useful old test scenarios into current frameworks; add missing runtime coverage and update current jobs/docs. No second browser build system.                                                                           |
| Browser admission          | Still a separate unresolved contract; no closed PR reviewed supplies it.                                                                                                                                                     |

Exact final line counts require implementing against the selected #584 and
Flamingo revisions. Historical PR totals are not estimates of remaining effort.
Keep source commit references in port commit messages and distinguish reused
code, adaptations, and new integration in the runtime PR description.
