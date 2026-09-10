# Credential activity backport to v0.21.4

This candidate starts at `v0.21.4` (`f0e3795`) and backports the credential
activity changes from #481 and #506. PR #533 targets
`codex/backport-base-v0.21.4`, which is pinned to that release commit.

The backport includes recording activity, paginated history, aggregate
metadata, clearing history, change listeners, and their schema and tests.
Imports use the original `walletkit-db` crate. The small
`Transaction::query_row_optional` helper is required by the activity code.

The SQLite engine, linkage, encryption open sequence, dependency lockfile,
workspace manifest, and toolchain pins remain those of v0.21.4. Other 0.22.0
changes are excluded. The native SQLite isolation fix is developed separately
on `codex/sqlite-isolation-v0.21.4` and is not part of this PR.

## Validation

Run the storage suite with the repository's pinned toolchain:

```sh
cargo test -p walletkit-core --lib storage:: --locked
cargo fmt --all -- --check
git diff --check
```

Build and test results recorded for the earlier combined activity/SQLite
candidate do not establish validation of this activity-only revision.
The PR description records the checks performed after splitting the changes.

## Release scope

Activity history adds its own cache table; the credential vault and envelope
formats remain unchanged. The activity schema and behavior follow #481/#506.
Validate activity persistence and host-app integration before distribution.

The source retains v0.21.4 version numbers. Assign a distinct reviewed
backport version before publishing any package or binary.
