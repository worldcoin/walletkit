//! `uniffi-bindgen-react-native` CLI wrapper for WalletKit.

use clap::Parser;

fn main() -> ubrn_cli::Result<()> {
    let args = ubrn_cli::cli::CliArgs::parse();
    args.run()
}
