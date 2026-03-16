//! Custom tracing layer that collects span durations for latency reporting.

use std::sync::{Arc, Mutex};
use std::time::Instant;

use tracing::span;
use tracing_subscriber::layer::Context;
use tracing_subscriber::Layer;

/// Collected latency entry: span name and elapsed duration.
pub type LatencyEntries = Arc<Mutex<Vec<(String, std::time::Duration)>>>;

/// A [`tracing_subscriber::Layer`] that records the duration of spans
/// with target `"walletkit_latency"`.
pub struct LatencyLayer {
    entries: LatencyEntries,
}

struct TimingStarted(Instant);

impl LatencyLayer {
    pub fn new(entries: LatencyEntries) -> Self {
        Self { entries }
    }
}

impl<S> Layer<S> for LatencyLayer
where
    S: tracing::Subscriber
        + for<'lookup> tracing_subscriber::registry::LookupSpan<'lookup>,
{
    fn on_new_span(
        &self,
        _attrs: &span::Attributes<'_>,
        id: &span::Id,
        ctx: Context<'_, S>,
    ) {
        if let Some(span) = ctx.span(id) {
            let mut extensions = span.extensions_mut();
            extensions.insert(TimingStarted(Instant::now()));
        }
    }

    fn on_close(&self, id: span::Id, ctx: Context<'_, S>) {
        if let Some(span) = ctx.span(&id) {
            let extensions = span.extensions();
            if let Some(started) = extensions.get::<TimingStarted>() {
                let elapsed = started.0.elapsed();
                let name = span.name().to_string();
                if let Ok(mut entries) = self.entries.lock() {
                    entries.push((name, elapsed));
                }
            }
        }
    }
}

/// Prints the latency report to stderr.
pub fn print_report(entries: &LatencyEntries, json: bool) {
    let entries = entries.lock().unwrap_or_else(|e| e.into_inner());
    if entries.is_empty() {
        return;
    }

    if json {
        let items: Vec<serde_json::Value> = entries
            .iter()
            .map(|(name, dur)| {
                serde_json::json!({
                    "span": name,
                    "ms": dur.as_millis(),
                })
            })
            .collect();
        eprintln!(
            "{}",
            serde_json::to_string_pretty(&items).unwrap_or_default()
        );
    } else {
        eprintln!("\nLatency:");
        let max_name_len = entries.iter().map(|(n, _)| n.len()).max().unwrap_or(0);
        for (name, dur) in entries.iter() {
            eprintln!(
                "  {:<width$}  {:>6}ms",
                name,
                dur.as_millis(),
                width = max_name_len
            );
        }
    }
}
