//! Repository automation for `WalletKit`.

mod kotlin;

use std::path::Path;

use clap::{Parser, Subcommand};
use eyre::Result;
use xshell::Shell;

#[derive(Parser)]
#[command(name = "cargo xtask", about = "Repository automation for WalletKit")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Kotlin/Android automation.
    Kotlin {
        #[command(subcommand)]
        command: kotlin::Command,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let sh = Shell::new()?;
    sh.change_dir(workspace_root());

    match cli.command {
        Command::Kotlin { command } => kotlin::run(&sh, &command),
    }
}

fn workspace_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask must be located directly inside the workspace root")
}
