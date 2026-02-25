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

        let formatted = format!("{} {message}", metadata.target());

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
