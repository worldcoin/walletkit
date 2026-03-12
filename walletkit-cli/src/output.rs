//! Output formatting helpers for human-readable and JSON modes.

/// Prints a raw JSON value wrapped in the standard envelope.
pub fn print_json_data(data: &serde_json::Value, json: bool) {
    if json {
        let envelope = serde_json::json!({ "ok": true, "data": data });
        println!(
            "{}",
            serde_json::to_string_pretty(&envelope).expect("serialization cannot fail")
        );
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(data).expect("serialization cannot fail")
        );
    }
}

/// Prints a success message.
pub fn print_success(msg: &str, json: bool) {
    if json {
        let envelope = serde_json::json!({ "ok": true, "data": { "message": msg } });
        println!(
            "{}",
            serde_json::to_string_pretty(&envelope).expect("serialization cannot fail")
        );
    } else {
        println!("{msg}");
    }
}
