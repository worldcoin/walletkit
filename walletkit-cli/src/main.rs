#![allow(missing_docs)]

//! `WalletKit` CLI — developer tool for World ID authenticator operations.

mod commands;
mod output;
mod provider;

use clap::Parser;
use commands::Cli;

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    if cli.verbose {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("debug")),
            )
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::new("warn"))
            .init();
    }

    // walletkit-core handles rustls provider installation via its ctor init.

    if let Err(err) = commands::run(cli).await {
        let json_mode = std::env::args().any(|a| a == "--json");
        if json_mode {
            let obj = serde_json::json!({
                "ok": false,
                "error": { "code": "cli_error", "message": format!("{err:#}") }
            });
            eprintln!("{}", serde_json::to_string_pretty(&obj).unwrap_or_default());
        } else {
            eprintln!("Error: {err:#}");
        }
        std::process::exit(1);
    }
}
