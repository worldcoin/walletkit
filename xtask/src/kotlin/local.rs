//! Maven Local publishing.

use eyre::{bail, Result, WrapErr as _};
use xshell::{cmd, Shell};

use super::build;

pub(super) fn run(sh: &Shell, version: &str) -> Result<()> {
    if version.trim().is_empty() {
        bail!("the Maven Local version must not be empty");
    }

    println!("Building WalletKit Android SDK {version} for local development...");
    build::run(sh, None)?;

    println!("Publishing WalletKit {version} to Maven Local...");
    let version_property = format!("-PversionName={version}");
    let _kotlin_dir = sh.push_dir("kotlin");
    cmd!(
        sh,
        "./gradlew :walletkit:publishToMavenLocal {version_property}"
    )
    .run()
    .wrap_err("failed to publish WalletKit to Maven Local")?;

    println!("Published org.world:walletkit:{version} to Maven Local.");
    Ok(())
}
