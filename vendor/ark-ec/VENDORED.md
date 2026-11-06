# Vendored `ark-ec` 0.6.0 with arkworks-rs/algebra#1187

**Temporary.** Delete this directory and the `[patch.crates-io]` entry in the workspace
`Cargo.toml` once arkworks publishes an `ark-ec` release containing
[arkworks-rs/algebra#1187](https://github.com/arkworks-rs/algebra/pull/1187).

## Why
With the `parallel` feature, `ark-ec` 0.6.0's MSM (`msm_bigint_wnaf`) unwraps
`rayon::ThreadPoolBuilder::build()`. On `wasm32-unknown-unknown` creating threads always fails, so
every such MSM panics in browsers. That includes the client-side OPRF commitment combination
(`taceo-oprf-core` `DLogCommitmentsShamir::combine_commitments`) that every uniqueness proof runs,
and Groth16 proving through `ark-groth16`.
`walletkit-web` cannot turn `parallel` off: `taceo-groth16` and `provekit-prover` enable it by
default. #1187 makes the MSM fall back to the current rayon context when the extra pool cannot
be created. That is the same computation, run on the current thread. Native builds are unaffected:
there the pool builds and the code path is unchanged.

## Contents
- `ark-ec` 0.6.0 as published on crates.io, identical except for the change below. Packaging
  metadata (`.cargo_vcs_info.json`, `.cargo-ok`, `Cargo.lock`, `Cargo.toml.orig`) removed.
- `src/scalar_mul/variable_base/mod.rs`: #1187 backported unchanged (`msm_bigint_wnaf_with_pool`
  plus its two tests). Upstream's #1112 `wasm32` guard, which #1187 replaced, was never released
  in 0.6.0, so the backport replaces the plain `.unwrap()`.
- `LICENSE-MIT` and `LICENSE-APACHE` from the original package.

## Verified
- `ark-ec` tests: 12 pass with `parallel` (including #1187's two tests that simulate
  unsupported thread creation), 10 without.
- `crates/walletkit-web/src/msm.rs` runs the OPRF combination MSM (full-size scalars) in a browser worker. It passes
  against this crate and panics (`unreachable`) against crates.io `ark-ec` 0.6.0.
