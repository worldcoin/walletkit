# Nargo Git dependency failures in WalletKit CI

Date: 2026-09-02

## Conclusion

The failing network operation is not Cargo fetching a Rust dependency. WalletKit's default `embed-zkeys` feature currently expands to `world-id-proof/embed-zk-artifacts`, which enables the native ownership-proof embed features. `world-id-proof 0.14.0` then runs `nargo compile` from its Cargo build script. Nargo `1.0.0-beta.11` resolves the circuit's two Git dependencies by running unauthenticated `git clone` commands under `$HOME/nargo`.

The repositories and pinned tags are public. The observed error proves that Git received an authentication challenge and could not prompt in the non-interactive ARC job, but the available evidence does not distinguish a GitHub edge response, ARC proxy, URL rewrite, or runner Git configuration. It should not be attributed more narrowly without ARC network and Git-config evidence.

The narrow downstream fix is to fetch the two immutable dependency commits in credential-isolated checkout steps, with credentials explicitly not persisted, then populate the exact Nargo cache paths before any Cargo command can execute build scripts. No token should be exported to a Cargo step or configured in global Git state.

## Evidence chain

### 1. WalletKit activates the build-time circuit compilation

Current main locks `world-id-proof 0.14.0` ([Cargo.lock](https://github.com/worldcoin/walletkit/blob/0a6424032853fdbe9b424f7b261cceb4e5188846/Cargo.lock#L9461-L9465)) from the workspace's `0.14` dependency ([Cargo.toml](https://github.com/worldcoin/walletkit/blob/0a6424032853fdbe9b424f7b261cceb4e5188846/Cargo.toml#L84-L86)).

`walletkit-core` enables its `embed-zkeys` feature by default, but that feature maps to upstream `embed-zk-artifacts`, not only Circom zkeys ([walletkit-core Cargo.toml](https://github.com/worldcoin/walletkit/blob/0a6424032853fdbe9b424f7b261cceb4e5188846/crates/walletkit-core/Cargo.toml#L94-L118)). The CLI also enables upstream `embed-zk-artifacts` directly ([walletkit-cli Cargo.toml](https://github.com/worldcoin/walletkit/blob/0a6424032853fdbe9b424f7b261cceb4e5188846/crates/walletkit-cli/Cargo.toml#L33-L36)).

In the published upstream source, `embed-zk-artifacts` includes `embed-noir-artifacts`, which includes both ownership embed features ([world-id-proof Cargo.toml](https://github.com/worldcoin/world-id-protocol/blob/19a670faa2a95267532b9ff70954cf75c6d6ecaa/crates/proof/Cargo.toml#L14-L29)). On non-WASM targets either ownership feature invokes `noir_artifacts::setup`; that function requires Nargo `1.0.0-beta.11` and executes `nargo compile` in `noir/ownership-proof` ([world-id-proof build.rs](https://github.com/worldcoin/world-id-protocol/blob/19a670faa2a95267532b9ff70954cf75c6d6ecaa/crates/proof/build.rs#L229-L317)).

The packaged circuit manifest names exactly these remote dependencies ([ownership-proof Nargo.toml](https://github.com/worldcoin/world-id-protocol/blob/19a670faa2a95267532b9ff70954cf75c6d6ecaa/crates/proof/noir/ownership-proof/Nargo.toml#L9-L11)):

- `https://github.com/TaceoLabs/oprf-service.git`, tag `taceo-oprf-v0.12.0`, directory `noir/eddsa_poseidon2`
- `https://github.com/TaceoLabs/noir-poseidon`, tag `v0.5.0-beta.0`, directory `poseidon2`

GitHub's repository API reports both repositories as public: [oprf-service](https://api.github.com/repos/TaceoLabs/oprf-service), [noir-poseidon](https://api.github.com/repos/TaceoLabs/noir-poseidon). The tags resolve to these commits:

- `taceo-oprf-v0.12.0` is annotated tag object `4cb460193e00148dc43aedadf280f73bf63bea29`, targeting commit `1ee7e0439c88e6c9c5468017ece602ad7a7ce94e` ([tag ref](https://api.github.com/repos/TaceoLabs/oprf-service/git/ref/tags/taceo-oprf-v0.12.0), [tag object](https://api.github.com/repos/TaceoLabs/oprf-service/git/tags/4cb460193e00148dc43aedadf280f73bf63bea29)).
- `v0.5.0-beta.0` targets commit `399574197066cdba30da969426b2cf50a232feb2` ([tag ref](https://api.github.com/repos/TaceoLabs/noir-poseidon/git/ref/tags/v0.5.0-beta.0)).

### 2. Nargo's cache and clone mechanism

The pinned Nargo release is commit `fd3925aaaeb76c76319f44590d135498ef41ea6c`. It constructs a dependency location as `$HOME/nargo/<URL domain>/<URL path>/<tag>` and uses only `Path::exists()` as the cache-hit test ([Nargo git.rs](https://github.com/noir-lang/noir/blob/fd3925aaaeb76c76319f44590d135498ef41ea6c/tooling/nargo_toml/src/git.rs#L5-L29)). Therefore the exact paths are:

```text
$HOME/nargo/github.com/TaceoLabs/oprf-service.git/taceo-oprf-v0.12.0
$HOME/nargo/github.com/TaceoLabs/noir-poseidon/v0.5.0-beta.0
```

On a miss it executes the equivalent of:

```text
git -c advice.detachedHead=false clone --depth 1 --branch TAG URL LOCATION
```

It supplies neither authentication nor retry handling. It also ignores the clone process's exit status and returns the target path, so the later missing-`Nargo.toml` error is a consequence of the failed clone ([Nargo git.rs](https://github.com/noir-lang/noir/blob/fd3925aaaeb76c76319f44590d135498ef41ea6c/tooling/nargo_toml/src/git.rs#L32-L64)). Manifest resolution immediately reads the dependency from that returned path ([Nargo lib.rs](https://github.com/noir-lang/noir/blob/fd3925aaaeb76c76319f44590d135498ef41ea6c/tooling/nargo_toml/src/lib.rs#L337-L375)). The `$HOME/nargo/.package-cache` lock only serializes resolvers that share a home directory; it does not authenticate, retry, or validate a cached checkout.

The two repositories close the full dependency graph. At the pinned commits, `eddsa_poseidon2` has a local `../babyjubjub` dependency and a remote `poseidon2` dependency ([manifest](https://github.com/TaceoLabs/oprf-service/blob/1ee7e0439c88e6c9c5468017ece602ad7a7ce94e/noir/eddsa_poseidon2/Nargo.toml)); `babyjubjub` also points to that same `poseidon2` ([manifest](https://github.com/TaceoLabs/oprf-service/blob/1ee7e0439c88e6c9c5468017ece602ad7a7ce94e/noir/babyjubjub/Nargo.toml)). `poseidon2` has only a local `../hash_utils` dependency ([manifest](https://github.com/TaceoLabs/noir-poseidon/blob/399574197066cdba30da969426b2cf50a232feb2/poseidon2/Nargo.toml)), and `hash_utils` has no dependencies ([manifest](https://github.com/TaceoLabs/noir-poseidon/blob/399574197066cdba30da969426b2cf50a232feb2/hash_utils/Nargo.toml)).

### 3. The failures match that mechanism and vary by clone

In PR #493's ARC Kotlin job, `world-id-proof` fails while Nargo is cloning `oprf-service` into the exact computed cache path. Git reports `could not read Username for 'https://github.com': No such device or address`, then Nargo reports the expected missing `noir/eddsa_poseidon2/Nargo.toml` ([job log](https://github.com/worldcoin/walletkit/actions/runs/33622170721/job/100221457224)).

In the same run's ARM64 MSRV test, the `oprf-service` clone succeeds, including roughly 240 MiB of Git-LFS filtering, and the next `noir-poseidon` clone fails with the same credential error and missing-manifest consequence ([job log](https://github.com/worldcoin/walletkit/actions/runs/33622170721/job/100221457115)). PR #480's ARC Kotlin job again fails on `oprf-service` in the same way ([job log](https://github.com/worldcoin/walletkit/actions/runs/33626157680/job/100237882922)). GitHub-hosted lint and Swift jobs passed in PR #493's run, which is consistent with a variable transport/runner failure rather than private repository access.

Git's official source constructs the `Username for ...` prompt as part of credential acquisition ([credential.c](https://github.com/git/git/blob/1630431f326e15fcde608827b5ff38422528eb59/credential.c#L241-L289)); its prompt path emits the read failure from a non-interactive terminal ([prompt.c](https://github.com/git/git/blob/1630431f326e15fcde608827b5ff38422528eb59/prompt.c#L46-L74)). This explains the error text, but not why the public request was challenged.

## Ranked mitigation

### 1. Authenticated, immutable, credential-isolated prefetch

Use the already pinned `actions/checkout` release to fetch each repository before Cargo, with all of the following properties:

- `ref` is the resolved commit SHA above, while the destination retains Nargo's tag-based directory name.
- `persist-credentials: false` prevents the checkout token from being configured for later commands.
- `sparse-checkout` includes only the directories needed by the manifests.
- `lfs: false` is explicit.
- The two exact target directories are replaced or verified before copying, because Nargo treats mere existence, including a partial previous clone, as valid.
- The workflow keeps `permissions: contents: read` and never places `${{ github.token }}` in a job-wide or Cargo-step environment.

Exact checkout inputs:

```yaml
- uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10 # v6.0.3
  with:
    repository: TaceoLabs/oprf-service
    ref: 1ee7e0439c88e6c9c5468017ece602ad7a7ce94e
    path: .nargo-cache/github.com/TaceoLabs/oprf-service.git/taceo-oprf-v0.12.0
    sparse-checkout: |
      noir/eddsa_poseidon2
      noir/babyjubjub
    persist-credentials: false
    lfs: false

- uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10 # v6.0.3
  with:
    repository: TaceoLabs/noir-poseidon
    ref: 399574197066cdba30da969426b2cf50a232feb2
    path: .nargo-cache/github.com/TaceoLabs/noir-poseidon/v0.5.0-beta.0
    sparse-checkout: |
      poseidon2
      hash_utils
    persist-credentials: false
    lfs: false
```

Cone-mode sparse checkout defaults to `true`, and v6.0.3 translates the entries to `git sparse-checkout set ...` ([checkout source](https://github.com/actions/checkout/blob/df4cb1c069e1874edd31b4311f1884172cec0e10/src/git-command-manager.ts#L196-L220)). When sparse checkout is enabled it fetches with `filter=blob:none` ([checkout source](https://github.com/actions/checkout/blob/df4cb1c069e1874edd31b4311f1884172cec0e10/src/git-source-provider.ts#L174-L186)). `lfs` defaults to `false`, and the implementation explicitly sets `GIT_LFS_SKIP_SMUDGE=1` in that case ([checkout action.yml](https://github.com/actions/checkout/blob/df4cb1c069e1874edd31b4311f1884172cec0e10/action.yml#L70-L85), [checkout source](https://github.com/actions/checkout/blob/df4cb1c069e1874edd31b4311f1884172cec0e10/src/git-command-manager.ts#L664-L674)). Therefore spelling out `lfs: false` is not required for behavior, but documents the important constraint and protects review clarity.

`persist-credentials: false` is the critical security boundary. Checkout documents that credentials otherwise remain available to later scripts and that this setting opts out ([checkout README](https://github.com/actions/checkout/blob/df4cb1c069e1874edd31b4311f1884172cec0e10/README.md#L21-L26)); its input is specifically whether to configure the token or SSH key ([checkout action.yml](https://github.com/actions/checkout/blob/df4cb1c069e1874edd31b4311f1884172cec0e10/action.yml#L52-L55)). GitHub creates a job-scoped `GITHUB_TOKEN` with permissions limited to the workflow repository ([GitHub token documentation](https://docs.github.com/en/actions/concepts/security/github_token)), and fork PR permissions are reduced to read-only for ordinary `pull_request` workflows ([workflow syntax](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#changing-the-permissions-in-a-forked-repository)). Credential isolation still matters because the later Cargo command executes dependency build scripts from the PR-selected dependency graph.

This fix is narrow: it changes CI acquisition, preserves current runtime artifact behavior, and eliminates both unauthenticated Nargo clones and the 240 MiB LFS fetch observed in the failing log. A persistent Actions cache is not required. If later added for performance, populate it only from validated immutable commits and never cache credentials; GitHub's cache guidance warns that low-trust PRs can restore base-branch caches ([cache security guidance](https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching#best-practices-for-using-caches-securely)).

### 2. Remove network-dependent Noir compilation from consumer builds upstream

The stronger architectural fix is for `world-id-proof` to publish or separately distribute ownership prover/verifier material with pinned hashes, or to move artifact generation into an explicit maintainer workflow. Ordinary consumers would then verify and embed immutable artifacts rather than compile Noir during `build.rs`.

WalletKit could also split its misleading `embed-zkeys` feature so Circom embedding does not automatically request ownership compilation, but doing that alone is not a narrow CI fix: existing mobile and CLI paths currently rely on embedded ownership material and would need a replacement artifact source plus behavior validation.

### 3. Cache only as an optimization after validation

Caching `$HOME/nargo` without validated prefetch is insufficient. Nargo does not record or check an expected commit and accepts any existing directory, including a partial clone. If caching is introduced, key it on the Nargo version and both exact commit SHAs, restore into a staging path, validate the checkout content or commit, then atomically install only the two expected directories. Do not cache checkout credential state.

## Rejected mitigations

- Exporting `GITHUB_TOKEN`, a PAT, or a Git `http.extraHeader` to the Cargo step would make credentials visible to arbitrary Cargo build scripts and fork-selected dependency code.
- Leaving `persist-credentials` enabled would deliberately make checkout credentials usable by later commands.
- Retrying Nargo's unauthenticated clones may reduce flakes but does not address the observed authentication challenge and repeats the large LFS transfer.
- A bare `$HOME/nargo` cache relies on Nargo's unsafe existence-only cache test.
- Changing public HTTPS URLs to credential-bearing URLs would put secrets in process arguments, configuration, or logs and would couple source manifests to one CI provider.

## Proportionate validation

The deterministic validation should make unexpected Git access fail:

1. Populate a fresh temporary home using the two sparse, commit-pinned source trees at the exact paths above.
2. Put a `git` wrapper that exits nonzero at the front of `PATH` for the compile step.
3. Run the repository-pinned `nargo 1.0.0-beta.11` against the published `world-id-proof 0.14.0/noir/ownership-proof` circuit. Success proves Nargo resolved the complete graph from the prefetched trees without invoking Git.
4. Run the relevant WalletKit command in `nix develop`, at minimum the feature-activation compile used by Kotlin (`cargo build -p walletkit --release --locked --features compress-zkeys,embed-zkeys,v3`) or a lower-cost no-codegen equivalent if time-constrained.
5. In CI, verify one ARC Kotlin job and one ARC all-features test job; those are the two independently observed failure paths.

Locally, `nix develop --command nargo --version` reports `nargo 1.0.0-beta.11` at Git commit `fd3925aaaeb76c76319f44590d135498ef41ea6c`, matching `world-id-proof`'s hard requirement.
