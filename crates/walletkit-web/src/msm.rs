//! Regression test for `ark-ec` multi-scalar multiplication in browsers.
//!
//! `taceo-groth16` and `provekit-prover` enable `ark-ec/parallel`. With it, `ark-ec` 0.6.0 builds
//! an extra rayon pool for every MSM and unwraps the result, which always fails on
//! `wasm32-unknown-unknown`. The client combines the OPRF nodes' commitments for every uniqueness
//! proof with exactly this MSM (`taceo-oprf-core` `DLogCommitmentsShamir::combine_commitments`),
//! so without the vendored arkworks-rs/algebra#1187 fix `generateProof` panics in the browser.

use ark_babyjubjub::{EdwardsAffine, EdwardsProjective, Fr};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use wasm_bindgen_test::wasm_bindgen_test;

#[wasm_bindgen_test]
fn oprf_commitment_combination_msm_runs_without_threads() {
    // Same inputs as the client's combination: one commitment per contributing node, weighted
    // by the nodes' Lagrange coefficients. Nodes 1, 2 and 4 give fractional coefficients, i.e.
    // full-size scalars. (Nodes 1, 2 and 3 give 3, -3 and 1, which take ark-ec's small-scalar
    // path and never reach the failing pool.)
    let parties = [1_u16, 2, 4];
    let lagrange: Vec<Fr> = taceo_oprf_core::shamir::lagrange_from_coeff(&parties);
    let generator = EdwardsAffine::generator();
    let commitments: Vec<EdwardsAffine> = [2_u64, 3, 5]
        .into_iter()
        .map(|k| (generator * Fr::from(k)).into_affine())
        .collect();

    let combined = EdwardsProjective::msm_unchecked(&commitments, &lagrange);

    let expected: EdwardsProjective = commitments
        .iter()
        .zip(&lagrange)
        .map(|(commitment, coefficient)| *commitment * coefficient)
        .sum();
    assert_eq!(combined, expected);
}
