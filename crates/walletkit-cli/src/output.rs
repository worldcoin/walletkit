//! Output formatting helpers for human-readable and JSON modes.

use std::io::IsTerminal as _;

const GREEN: &str = "\x1b[32m";
const RED: &str = "\x1b[31m";
const RESET: &str = "\x1b[0m";

fn colorize(label: &str, color: &str) -> String {
    if std::io::stdout().is_terminal() {
        format!("{color}{label}{RESET}")
    } else {
        label.to_string()
    }
}

/// Returns `[PASS]` colored green when stdout is a TTY, otherwise plain.
#[must_use]
pub fn pass_label() -> String {
    colorize("[PASS]", GREEN)
}

/// Returns `[FAIL]` colored red when stdout is a TTY, otherwise plain.
#[must_use]
pub fn fail_label() -> String {
    colorize("[FAIL]", RED)
}

/// Prints a raw JSON value wrapped in the standard envelope.
pub fn print_json_data(data: &serde_json::Value, json: bool) {
    if json {
        let envelope = serde_json::json!({ "ok": true, "data": data });
        match serde_json::to_string_pretty(&envelope) {
            Ok(s) => println!("{s}"),
            Err(e) => eprintln!("error: failed to serialize output: {e}"),
        }
    } else {
        match serde_json::to_string_pretty(data) {
            Ok(s) => println!("{s}"),
            Err(e) => eprintln!("error: failed to serialize output: {e}"),
        }
    }
}

/// Prints a success message.
pub fn print_success(msg: &str, json: bool) {
    if json {
        let envelope = serde_json::json!({ "ok": true, "data": { "message": msg } });
        match serde_json::to_string_pretty(&envelope) {
            Ok(s) => println!("{s}"),
            Err(e) => eprintln!("error: failed to serialize output: {e}"),
        }
    } else {
        println!("{msg}");
    }
}
