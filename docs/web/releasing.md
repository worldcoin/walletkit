# Release the browser package

This page describes how `@worldcoin/walletkit-web` is checked, published to npm,
and rolled back. The [`web.yml`](https://github.com/worldcoin/walletkit/blob/main/.github/workflows/web.yml) workflow builds,
tests, and publishes the package. Merging the release pull request, configuring
trusted publishing, and rolling back are manual.

## Checks before release

For pull requests and pushes to `main` that change the package or its Rust
dependencies, `web.yml` builds and tests the package and verifies the packed
tarball. It publishes nothing.

## Publish a release

The package shares its version with the `walletkit` crate. To publish it, merge
the release pull request that release-plz opens. release-plz then publishes the
crates and a GitHub release tagged `vX.Y.Z`, and that release starts `web.yml`,
which does the following:

1. Builds and tests the package as for a pull request.
1. Stamps `X.Y.Z` from the tag into `package.json` and packs the tarball. A tag
   that isn't of the form `vX.Y.Z` fails the build.
1. In a second job, in the `production` environment, publishes that exact tarball
   to npm with provenance.

The workflow publishes a version with a pre-release suffix, such as
`X.Y.Z-rc.1`, under the `next` dist-tag instead of `latest`. If the version is
already on npm, the publish job skips it, so you can rerun a failed release safely.

## Configure trusted publishing

The workflow authenticates to npm with
[trusted publishing](https://docs.npmjs.com/trusted-publishers), so the repository
stores no npm token. This is a one-time setup for an owner of the npm package. On
npmjs.com, in the `@worldcoin/walletkit-web` package settings, add a trusted
publisher with these values:

| Setting     | Value                 |
| ----------- | --------------------- |
| Repository  | `worldcoin/walletkit` |
| Workflow    | `web.yml`             |
| Environment | `production`          |

## Roll back a release

npm doesn't let you reliably replace a published version, so a rollback is a
deprecation followed by a fix:

1. Deprecate the bad version:

   ```sh
   npm deprecate @worldcoin/walletkit-web@X.Y.Z "<reason>"
   ```

1. Publish a fixed version through the normal release process.

Don't rely on `npm unpublish`.
