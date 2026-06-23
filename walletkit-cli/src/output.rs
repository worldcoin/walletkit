//! Output formatting helpers for human-readable and JSON modes.

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
