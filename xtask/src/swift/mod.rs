//! Swift/iOS automation.

mod archive;
mod build;
mod local;
mod package;
mod test;

use std::path::PathBuf;

use clap::{Args, Subcommand};
use eyre::Result;
use xshell::Shell;

/// Swift/iOS tasks.
#[derive(Subcommand)]
pub enum Command {
    /// Build iOS libraries, generate Swift bindings, and create an `XCFramework`.
    Build(BuildOptions),

    /// Build the Swift bindings and run the iOS foreign-binding tests.
    Test(TestOptions),

    /// Build a Swift package for local development.
    Local,

    /// Generate the release `Package.swift` manifest.
    Archive(ArchiveOptions),
}

/// Options for building the Swift/iOS library.
#[derive(Args)]
pub struct BuildOptions {
    /// Directory in which to create the `XCFramework` and generated sources.
    ///
    /// Relative paths are resolved from the `swift` directory. Defaults to `swift`.
    #[arg(value_name = "OUTPUT_DIR")]
    output_dir: Option<PathBuf>,
}

/// Options for running Swift foreign-binding tests.
#[derive(Args)]
pub struct TestOptions {
    /// Test an existing `swift/WalletKit.xcframework` without rebuilding it.
    #[arg(long)]
    skip_build: bool,
}

/// Options for generating the release Swift package manifest.
#[derive(Args)]
pub struct ArchiveOptions {
    /// URL of the zipped `XCFramework` release asset.
    #[arg(long)]
    asset_url: String,

    /// Swift Package Manager checksum of the release asset.
    #[arg(long)]
    checksum: String,

    /// `WalletKit` release version recorded in the generated manifest.
    #[arg(long)]
    release_version: String,
}

/// Runs a Swift/iOS task.
pub fn run(sh: &Shell, command: &Command) -> Result<()> {
    match command {
        Command::Build(options) => build::run(sh, options.output_dir.as_deref()),
        Command::Test(options) => test::run(sh, options.skip_build),
        Command::Local => local::run(sh),
        Command::Archive(options) => archive::run(
            sh,
            &options.asset_url,
            &options.checksum,
            &options.release_version,
        ),
    }
}
