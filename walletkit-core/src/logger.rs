use std::{
    fmt,
    sync::{mpsc, Arc, Mutex, OnceLock},
    thread,
};

use tracing::{Event, Level, Subscriber};
use tracing_subscriber::{
    layer::{Context, SubscriberExt},
    registry::LookupSpan,
    EnvFilter, Layer, Registry,
};

/// Trait representing the minimal foreign logging bridge used by `WalletKit`.
///
/// `WalletKit` emits tracing events and forwards formatted messages with an
/// explicit severity `level`.
///
/// # Rust example
///
/// ```rust
/// use std::sync::Arc;
/// use walletkit_core::logger::{init_logging, LogLevel, Logger};
///
/// struct AppLogger;
///
/// impl Logger for AppLogger {
///     fn log(&self, level: LogLevel, message: String) {
///         println!("[{level:?}] {message}");
///     }
/// }
///
/// init_logging(Arc::new(AppLogger), Some(LogLevel::Debug));
/// ```
///
/// # Swift example
///
/// ```swift
/// final class WalletKitLoggerBridge: WalletKit.Logger {
///     static let shared = WalletKitLoggerBridge()
///
///     func log(level: WalletKit.LogLevel, message: String) {
///         switch level {
///         case .trace, .debug:
///             print("[DEBUG] \(message)")
///         case .info:
///             print("[INFO] \(message)")
///         case .warn:
///             print("[WARN] \(message)")
///         case .error:
///             fputs("[ERROR] \(message)\n", stderr)
///         @unknown default:
///             fputs("[UNKNOWN] \(message)\n", stderr)
///         }
///     }
/// }
///
/// WalletKit.initLogging(logger: WalletKitLoggerBridge.shared, level: .debug)
/// ```
#[uniffi::export(with_foreign)]
pub trait Logger: Sync + Send {
    /// Receives a log `message` with its corresponding `level`.
    fn log(&self, level: LogLevel, message: String);
}

/// Enumeration of possible log levels for foreign logger callbacks.
#[derive(Debug, Clone, Copy, uniffi::Enum)]
pub enum LogLevel {
    /// Very detailed diagnostic messages.
    Trace,
    /// Debug-level messages.
    Debug,
    /// Informational messages.
    Info,
    /// Warning messages.
    Warn,
    /// Error messages.
    Error,
}

const fn log_level(level: Level) -> LogLevel {
    match level {
        Level::TRACE => LogLevel::Trace,
        Level::DEBUG => LogLevel::Debug,
        Level::INFO => LogLevel::Info,
        Level::WARN => LogLevel::Warn,
        Level::ERROR => LogLevel::Error,
    }
}

#[derive(Default)]
struct EventFieldVisitor {
    message: Option<String>,
    fields: Vec<(String, String)>,
}

impl tracing::field::Visit for EventFieldVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn fmt::Debug) {
        let value = format!("{value:?}");
        if field.name() == "message" {
            self.message = Some(value);
        } else {
            self.fields.push((field.name().to_string(), value));
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.message = Some(value.to_string());
        } else {
            self.fields
                .push((field.name().to_string(), value.to_string()));
        }
    }
}

/// Forwards walletkit tracing events to the foreign logger.
struct ForeignLoggerLayer;

struct LogEvent {
    level: LogLevel,
    message: String,
}

// Log events are pushed into this channel by `ForeignLoggerLayer::on_event`
// and delivered to the foreign callback on a dedicated thread.
//
// This architecture is required because UniFFI foreign callbacks crash with
// EXC_BAD_ACCESS when invoked synchronously from within a UniFFI future-poll
// context (`rust_call_with_out_status`). The nested FFI boundary crossing
// corrupts state. By decoupling collection from delivery through a channel,
// the tracing layer never makes an FFI call — it only pushes to an in-process
// queue — and the dedicated delivery thread calls `Logger::log` from a clean
// stack with no active FFI frames.
static LOG_CHANNEL: OnceLock<Mutex<mpsc::Sender<LogEvent>>> = OnceLock::new();
static LOGGING_INITIALIZED: OnceLock<()> = OnceLock::new();

impl<S> Layer<S> for ForeignLoggerLayer
where
    S: Subscriber + for<'span> LookupSpan<'span>,
{
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let Some(sender) = LOG_CHANNEL.get() else {
            return;
        };

        let mut visitor = EventFieldVisitor::default();
        event.record(&mut visitor);
        let metadata = event.metadata();

        let mut message = visitor.message.unwrap_or_default();
        if !visitor.fields.is_empty() {
            let extras = visitor
                .fields
                .iter()
                .map(|(name, value)| format!("{name}={value}"))
                .collect::<Vec<_>>()
                .join(" ");
            if message.is_empty() {
                message = extras;
            } else {
                message = format!("{message} {extras}");
            }
        }
        if message.is_empty() {
            message = metadata.name().to_string();
        }

        let formatted =
            sanitize_hex_secrets(format!("{} {message}", metadata.target()));

        if let Ok(sender) = sender.lock() {
            let _ = sender.send(LogEvent {
                level: log_level(*metadata.level()),
                message: formatted,
            });
        }
    }
}

const fn log_level_filter(level: LogLevel) -> &'static str {
    match level {
        LogLevel::Trace => "trace",
        LogLevel::Debug => "debug",
        LogLevel::Info => "info",
        LogLevel::Warn => "warn",
        LogLevel::Error => "error",
    }
}

// Only these crates are promoted to the caller-requested level.
// Everything else stays at the baseline (`info`). This avoids
// flooding the logger with internal noise from infrastructure crates.
const APP_CRATES: &[&str] = &[
    "walletkit",
    "walletkit_core",
    "world_id_core",
    "world_id_proof",
    "world_id_authenticator",
    "world_id_primitives",
    "taceo_oprf",
    "taceo_oprf_client",
    "taceo_oprf_core",
    "taceo_oprf_types",
    "semaphore_rs",
];

fn build_env_filter(level: Option<LogLevel>) -> EnvFilter {
    if let Ok(filter) = EnvFilter::try_from_default_env() {
        return filter;
    }

    let level_str = level.map_or("info", log_level_filter);

    let needs_per_crate = matches!(level, Some(LogLevel::Trace | LogLevel::Debug));
    if !needs_per_crate {
        return EnvFilter::new(level_str);
    }

    // e.g. "walletkit=debug,walletkit_core=debug,...,info"
    let mut directives = String::new();
    for crate_name in APP_CRATES {
        directives.push_str(crate_name);
        directives.push('=');
        directives.push_str(level_str);
        directives.push(',');
    }
    directives.push_str("info");
    EnvFilter::new(directives)
}

/// Emits a message at the given level through `WalletKit`'s tracing pipeline.
///
/// Useful for verifying that the logging bridge is wired up correctly.
#[uniffi::export]
pub fn emit_log(level: LogLevel, message: String) {
    let message = message.into_boxed_str();
    let message = message.as_ref();

    match level {
        LogLevel::Trace => tracing::trace!(target: "walletkit", "{message}"),
        LogLevel::Debug => tracing::debug!(target: "walletkit", "{message}"),
        LogLevel::Info => tracing::info!(target: "walletkit", "{message}"),
        LogLevel::Warn => tracing::warn!(target: "walletkit", "{message}"),
        LogLevel::Error => tracing::error!(target: "walletkit", "{message}"),
    }
}

/// Initializes `WalletKit` tracing and registers a foreign logger sink.
///
/// `level` controls the minimum severity for `WalletKit` and its direct
/// dependencies (taceo, world-id, semaphore). All other crates remain at
/// `Info` regardless of this setting. Pass `None` to default to `Info`.
/// The `RUST_LOG` environment variable, when set, always takes precedence.
///
/// This function is idempotent. The first call wins; subsequent calls are no-ops.
///
/// # Panics
///
/// Panics if the dedicated logger delivery thread cannot be spawned.
#[uniffi::export]
pub fn init_logging(logger: Arc<dyn Logger>, level: Option<LogLevel>) {
    if LOGGING_INITIALIZED.get().is_some() {
        return;
    }

    let (tx, rx) = mpsc::channel::<LogEvent>();
    let _ = LOG_CHANNEL.set(Mutex::new(tx));

    thread::Builder::new()
        .name("walletkit-logger".into())
        .spawn(move || {
            for event in rx {
                logger.log(event.level, event.message);
            }
        })
        .expect("failed to spawn walletkit logger thread");

    let _ = tracing_log::LogTracer::init();

    let filter = build_env_filter(level);
    let subscriber = Registry::default().with(filter).with(ForeignLoggerLayer);

    if tracing::subscriber::set_global_default(subscriber).is_ok() {
        let _ = LOGGING_INITIALIZED.set(());
    }
}

/// Minimum contiguous hex digits to treat as a potential secret.
const HEX_SECRET_MIN_LEN: usize = 12;

/// Replaces hex sequences of [`HEX_SECRET_MIN_LEN`] or more digits with a
/// redacted form showing only the first and last two hex characters.
/// An optional `0x` prefix is preserved in the output.
///
/// Returns `input` unmodified (zero-allocation) when no redaction is needed.
fn sanitize_hex_secrets(input: String) -> String {
    if !has_long_hex_run(input.as_bytes()) {
        return input;
    }

    let bytes = input.as_bytes();
    let len = bytes.len();
    let mut out = String::with_capacity(len);
    let mut i = 0;

    while i < len {
        let has_prefix = i + 1 < len
            && bytes[i] == b'0'
            && (bytes[i + 1] == b'x' || bytes[i + 1] == b'X');
        let digit_start = if has_prefix { i + 2 } else { i };

        let mut j = digit_start;
        while j < len && bytes[j].is_ascii_hexdigit() {
            j += 1;
        }

        let hex_len = j - digit_start;
        if hex_len >= HEX_SECRET_MIN_LEN {
            if has_prefix {
                out.push_str("0x");
            }
            out.push(char::from(bytes[digit_start]));
            out.push(char::from(bytes[digit_start + 1]));
            out.push_str("..");
            out.push(char::from(bytes[j - 2]));
            out.push(char::from(bytes[j - 1]));
            i = j;
        } else if j > i {
            out.push_str(&input[i..j]);
            i = j;
        } else {
            // Copy one full UTF-8 character. Non-ASCII leading bytes
            // are never hex digits, so `i` is always at a char boundary.
            let b = bytes[i];
            let char_len = if b < 0x80 {
                1
            } else if b < 0xE0 {
                2
            } else if b < 0xF0 {
                3
            } else {
                4
            };
            out.push_str(&input[i..i + char_len]);
            i += char_len;
        }
    }

    out
}

fn has_long_hex_run(bytes: &[u8]) -> bool {
    let mut run: usize = 0;
    for &b in bytes {
        if b.is_ascii_hexdigit() {
            run += 1;
            if run >= HEX_SECRET_MIN_LEN {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_hex_passes_through() {
        let input = "tx hash is abcdef1";
        assert_eq!(sanitize_hex_secrets(input.to_string()), input);
    }

    #[test]
    fn long_hex_is_redacted() {
        let input = "key=deadbeefcafebabe1234567890abcdef1234567890abcdef end";
        assert_eq!(sanitize_hex_secrets(input.to_string()), "key=de..ef end");
    }

    #[test]
    fn hex_with_0x_prefix() {
        let input = "addr 0xdeadbeefcafebabe1234567890abcdef1234567890abcdef end";
        assert_eq!(sanitize_hex_secrets(input.to_string()), "addr 0xde..ef end");
    }

    #[test]
    fn multiple_secrets_redacted() {
        let a = "a".repeat(32);
        let b = "b".repeat(32);
        let input = format!("x={a} y={b}");
        assert_eq!(sanitize_hex_secrets(input), "x=aa..aa y=bb..bb");
    }

    #[test]
    fn exactly_threshold_is_redacted() {
        let input = "a".repeat(HEX_SECRET_MIN_LEN);
        assert_eq!(sanitize_hex_secrets(input), "aa..aa");
    }

    #[test]
    fn below_threshold_passes() {
        let input = "a".repeat(HEX_SECRET_MIN_LEN - 1);
        assert_eq!(sanitize_hex_secrets(input.clone()), input);
    }

    #[test]
    fn no_hex_passes_through() {
        let input = "hello world, no hex here!";
        assert_eq!(sanitize_hex_secrets(input.to_string()), input);
    }

    #[test]
    fn empty_string() {
        assert_eq!(sanitize_hex_secrets(String::new()), "");
    }

    #[test]
    fn uppercase_hex_redacted() {
        let input = "DEADBEEFCAFEBABE1234567890ABCDEF1234567890ABCDEF";
        assert_eq!(sanitize_hex_secrets(input.to_string()), "DE..EF");
    }

    #[test]
    fn mixed_text_and_hex() {
        let secret = "f".repeat(64);
        let input = format!("user=alice secret={secret} action=login");
        assert_eq!(
            sanitize_hex_secrets(input),
            "user=alice secret=ff..ff action=login"
        );
    }

    #[test]
    fn utf8_preserved_alongside_hex_redaction() {
        let secret = "a".repeat(32);
        let input = format!("clé={secret} résumé");
        assert_eq!(
            sanitize_hex_secrets(input),
            "clé=aa..aa résumé"
        );
    }

    #[test]
    fn multibyte_utf8_no_hex() {
        let input = "café naïve 日本語".to_string();
        assert_eq!(sanitize_hex_secrets(input.clone()), input);
    }

    #[test]
    fn no_alloc_when_clean() {
        let input = String::from("no secrets here");
        let ptr = input.as_ptr();
        let output = sanitize_hex_secrets(input);
        assert_eq!(output.as_ptr(), ptr, "should return same allocation");
    }
}
