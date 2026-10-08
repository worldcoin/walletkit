# Release WalletKit

This page describes how a WalletKit release is prepared and published. All
packages share one version, `X.Y.Z`, taken from the workspace `Cargo.toml`, and
one release publishes all of them:

| Package                                                                       | Published to                                                                             | Workflow                     |
| ----------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- | ---------------------------- |
| Rust crates `walletkit`, `walletkit-core`, `walletkit-db`, `walletkit-sqlite` | crates.io                                                                                | [`release.yml`]              |
| Swift package                                                                 | [`worldcoin/walletkit-swift`](https://github.com/worldcoin/walletkit-swift), tag `X.Y.Z` | [`release-swift-kotlin.yml`] |
| Kotlin library `org.world:walletkit`                                          | GitHub Packages                                                                          | [`release-swift-kotlin.yml`] |
| Browser package `@worldcoin/walletkit-web`                                    | npm                                                                                      | [`web.yml`]                  |

## How a release happens

[release-plz](https://release-plz.dev) drives the release from the
[Conventional Commits](https://www.conventionalcommits.org/) on `main`:

1. On every push to `main`, `release.yml` runs release-plz. It opens or updates a
   release pull request, labeled `release`, that bumps the workspace version and
   adds the new commits to
   [`crates/walletkit/CHANGELOG.md`](https://github.com/worldcoin/walletkit/blob/main/crates/walletkit/CHANGELOG.md).
1. A maintainer reviews and merges the release pull request. The bot that opens it
   can't merge it.
1. On the push of that merge, release-plz publishes the crates whose version isn't
   on crates.io yet, and it creates the GitHub release `vX.Y.Z`.
1. Publishing the GitHub release starts `release-swift-kotlin.yml` and `web.yml`,
   which build and publish the Swift, Kotlin, and browser packages from the
   released commit.

release-plz authenticates to GitHub with the `WALLETKIT_BOT_TOKEN` secret, not with
the workflow's default token. Events created with the default token don't start
other workflows, so the bot token is what lets the GitHub release trigger the
package workflows.

[`release-plz.toml`](https://github.com/worldcoin/walletkit/blob/main/release-plz.toml)
configures which crates are published and which crate's changelog and GitHub
release represent the workspace.

## Crates

The `release.yml` job runs in the `production` environment and publishes to
crates.io with [trusted publishing](https://crates.io/docs/trusted-publishing): it
has the `id-token: write` permission and holds no crates.io token. Each published
crate must list this repository's `release.yml` as a trusted publisher on
crates.io.

Trusted publishing can't create a crate. To add a new published crate, publish its
first version by hand, configure its trusted publisher, and then add it to
`release-plz.toml`.

## Swift

The `build-swift` job runs on macOS:

1. Builds the XCFramework with `cargo xtask swift build`, using the features in
   the workflow's `WALLETKIT_CARGO_FEATURES` variable.
1. Creates a draft release `X.Y.Z` in `worldcoin/walletkit-swift` and uploads the
   zipped XCFramework to it.
1. Generates `Package.swift` with the asset URL and checksum, commits it with the
   Swift sources to `walletkit-swift`, and tags the commit `X.Y.Z`.
1. Publishes the draft and marks it as the latest release.

The job writes to `walletkit-swift` with `WALLETKIT_BOT_TOKEN`.

## Kotlin

The `prepare-kotlin` job builds the native library for the four Android targets in
parallel, with `nix/build-android.sh`. The `publish-kotlin` job then assembles the
`jniLibs`, generates the Kotlin bindings, and runs `./gradlew walletkit:publish`,
which publishes `org.world:walletkit:X.Y.Z` to GitHub Packages. Gradle reads the
version from the workspace `Cargo.toml`.

## Browser package

The `web.yml` workflow builds and tests the package, stamps `X.Y.Z` from the
release tag into `package.json`, and packs the tarball. A tag that isn't of the
form `vX.Y.Z` fails the build. A second job, in the `production` environment,
publishes that exact tarball to npm with provenance:

- A version with a pre-release suffix, such as `X.Y.Z-rc.1`, goes to the `next`
  dist-tag instead of `latest`.
- If the version is already on npm, the job skips publishing.

The job authenticates to npm with
[trusted publishing](https://docs.npmjs.com/trusted-publishers), so the repository
stores no npm token. This is a one-time setup for an owner of the npm package. On
npmjs.com, in the `@worldcoin/walletkit-web` package settings, add a trusted
publisher with these values:

| Setting     | Value                 |
| ----------- | --------------------- |
| Repository  | `worldcoin/walletkit` |
| Workflow    | `web.yml`             |
| Environment | `production`          |

## Recover from a failed release

- **Crates.** To publish a version that is merged on `main` but missing from
  crates.io, run `release.yml` manually from the **Actions** tab. A manual run only
  publishes; it doesn't open a release pull request.
- **Swift, Kotlin, and the browser package.** Rerun the failed jobs of the
  workflow run that the GitHub release started. The npm job skips a version that is
  already published.

## Roll back a release

Published versions can't be replaced, so a rollback marks the bad version and is
followed by a fixed release:

1. Mark the bad version:
   - Crates: `cargo yank --version X.Y.Z <crate>` for each published crate.
   - Browser package:
     `npm deprecate @worldcoin/walletkit-web@X.Y.Z "<reason>"`. Don't rely on
     `npm unpublish`.
1. Release a fixed version through the normal process.

[`release.yml`]: https://github.com/worldcoin/walletkit/blob/main/.github/workflows/release.yml
[`release-swift-kotlin.yml`]: https://github.com/worldcoin/walletkit/blob/main/.github/workflows/release-swift-kotlin.yml
[`web.yml`]: https://github.com/worldcoin/walletkit/blob/main/.github/workflows/web.yml
