//! Kotlin/Android automation.

mod build;
mod local;
mod test;

use std::path::PathBuf;

use clap::{Args, Subcommand};
use eyre::Result;
use xshell::Shell;

/// Kotlin/Android tasks.
#[derive(Subcommand)]
pub enum Command {
    /// Build Android native libraries and generate Kotlin bindings.
    Build(BuildOptions),

    /// Build host bindings and run the Kotlin/JVM tests.
    Test,

    /// Build the Android library and publish it to Maven Local.
    Local(LocalOptions),
}

/// Options for building the Kotlin/Android library.
#[derive(Args)]
pub struct BuildOptions {
    /// Use prebuilt Android libraries instead of building them.
    ///
    /// The directory must use the layout produced by the CI build matrix:
    /// `android-<target>/libwalletkit_core.a`.
    #[arg(long, value_name = "DIR")]
    artifacts_dir: Option<PathBuf>,

    /// Build an unoptimized binary with full debug symbols, for native
    /// (LLDB-via-NDK) source-level debugging of Rust code. Not suitable for
    /// distribution. Ignored when `--artifacts-dir` is set.
    #[arg(long)]
    debug: bool,
}

/// Options for publishing the Kotlin/Android library locally.
#[derive(Args)]
pub struct LocalOptions {
    /// Version under which to publish the library.
    #[arg(value_name = "VERSION")]
    version: String,

    /// Build an unoptimized binary with full debug symbols, for native
    /// (LLDB-via-NDK) source-level debugging of Rust code. Not suitable for
    /// distribution.
    #[arg(long)]
    debug: bool,
}

/// Runs a Kotlin/Android task.
pub fn run(sh: &Shell, command: &Command) -> Result<()> {
    match command {
        Command::Build(options) => build::run(
            sh,
            options.artifacts_dir.as_deref(),
            build::Profile::from_debug_flag(options.debug),
        ),
        Command::Test => test::run(sh),
        Command::Local(options) => local::run(sh, &options.version, options.debug),
    }
}
