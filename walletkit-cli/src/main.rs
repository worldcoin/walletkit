#![allow(missing_docs)]

//! `WalletKit` CLI — developer tool for World ID authenticator operations.

mod commands;
mod latency;
mod output;
mod provider;

use std::sync::{Arc, Mutex};

use clap::Parser;
use commands::Cli;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let latency_entries: latency::LatencyEntries = Arc::new(Mutex::new(Vec::new()));
    let show_latency = cli.latency;
    let json_mode = cli.json;

    // Build the subscriber with optional latency layer.
    let env_filter = if cli.verbose {
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("debug"))
    } else {
        EnvFilter::new("warn")
    };

    let env_filter = if show_latency {
        env_filter.add_directive("walletkit_latency=trace".parse().unwrap())
    } else {
        env_filter
    };

    let fmt_layer = tracing_subscriber::fmt::layer();

    let registry = tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt_layer);

    if show_latency {
        let latency_layer = latency::LatencyLayer::new(latency_entries.clone());
        registry.with(latency_layer).init();
    } else {
        registry.init();
    }

    // walletkit-core handles rustls provider installation via its ctor init.

    if let Err(err) = commands::run(cli).await {
        let json_flag = std::env::args().any(|a| a == "--json");
        if json_flag {
            let obj = serde_json::json!({
                "ok": false,
                "error": { "code": "cli_error", "message": format!("{err:#}") }
            });
            eprintln!("{}", serde_json::to_string_pretty(&obj).unwrap_or_default());
        } else {
            eprintln!("Error: {err:#}");
        }
        if show_latency {
            latency::print_report(&latency_entries, json_mode);
        }
        std::process::exit(1);
    }

    if show_latency {
        latency::print_report(&latency_entries, json_mode);
    }
}
