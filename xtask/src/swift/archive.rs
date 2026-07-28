//! Release Swift package manifest generation.

use eyre::{ensure, Result, WrapErr as _};
use xshell::{cmd, Shell};

use super::package;

const PACKAGE_TEMPLATE: &str = "swift/Package.swift.template";
const RELEASE_MANIFEST: &str = "Package.swift";

pub(super) fn run(
    sh: &Shell,
    asset_url: &str,
    checksum: &str,
    release_version: &str,
) -> Result<()> {
    ensure!(!asset_url.trim().is_empty(), "asset URL must not be empty");
    ensure!(!checksum.trim().is_empty(), "checksum must not be empty");
    ensure!(
        !release_version.trim().is_empty(),
        "release version must not be empty"
    );

    println!("Creating release Package.swift for WalletKit {release_version}...");
    let template = sh
        .read_file(PACKAGE_TEMPLATE)
        .wrap_err_with(|| format!("failed to read {PACKAGE_TEMPLATE}"))?;
    let manifest =
        package::release_manifest(&template, asset_url, checksum, release_version)?;
    sh.write_file(RELEASE_MANIFEST, manifest)
        .wrap_err_with(|| format!("failed to write {RELEASE_MANIFEST}"))?;

    cmd!(sh, "swiftlint lint --autocorrect {RELEASE_MANIFEST}")
        .run()
        .wrap_err("failed to lint the release Package.swift")?;

    println!("Package.swift built successfully for version {release_version}.");
    Ok(())
}
