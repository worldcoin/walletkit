//! Local Swift package generation.

use std::path::Path;

use eyre::{Result, WrapErr as _};
use xshell::Shell;

use super::build::Profile;
use super::{build, package};

const FRAMEWORK_NAME: &str = "WalletKit.xcframework";
const LOCAL_BUILD_DIR: &str = "swift/local_build/walletkit-swift";
const PACKAGE_TEMPLATE: &str = "swift/Package.swift.template";

pub(super) fn run(sh: &Shell, debug: bool) -> Result<()> {
    let profile = if debug {
        Profile::Debug
    } else {
        Profile::Release
    };

    println!("Building {FRAMEWORK_NAME} for local iOS development...");

    sh.remove_path(LOCAL_BUILD_DIR)?;
    sh.create_dir(LOCAL_BUILD_DIR)?;
    build::run(sh, Some(Path::new("local_build/walletkit-swift")), profile)?;

    println!("Creating Package.swift for local development...");
    let template = sh
        .read_file(PACKAGE_TEMPLATE)
        .wrap_err_with(|| format!("failed to read {PACKAGE_TEMPLATE}"))?;
    let manifest = package::local_manifest(&template, FRAMEWORK_NAME)?;
    let manifest_path = Path::new(LOCAL_BUILD_DIR).join("Package.swift");
    sh.write_file(&manifest_path, manifest)
        .wrap_err_with(|| format!("failed to write {}", manifest_path.display()))?;

    println!("Swift package built successfully.");
    println!("Package location: {LOCAL_BUILD_DIR}");
    println!("Add it with: .package(path: \"{LOCAL_BUILD_DIR}\")");
    Ok(())
}
