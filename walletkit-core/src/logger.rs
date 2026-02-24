use std::{
    fmt,
    sync::{Arc, OnceLock},
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
/// init_logging(Arc::new(AppLogger));
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
/// WalletKit.initLogging(logger: WalletKitLoggerBridge.shared)
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

impl<S> Layer<S> for ForeignLoggerLayer
where
    S: Subscriber + for<'span> LookupSpan<'span>,
{
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let Some(logger) = LOGGER_INSTANCE.get() else {
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
        logger.log(log_level(*metadata.level()), formatted);
    }
}

static LOGGER_INSTANCE: OnceLock<Arc<dyn Logger>> = OnceLock::new();
static LOGGING_INITIALIZED: OnceLock<()> = OnceLock::new();

/// Initializes `WalletKit` tracing and registers a foreign logger sink.
///
/// This function is idempotent. The first call wins; subsequent calls are no-ops.
#[uniffi::export]
pub fn init_logging(logger: Arc<dyn Logger>) {
    let _ = LOGGER_INSTANCE.set(logger);
    if LOGGING_INITIALIZED.get().is_some() {
        return;
    }

    let _ = tracing_log::LogTracer::init();

    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let subscriber = Registry::default()
        .with(filter)
        .with(ForeignLoggerLayer);

    if tracing::subscriber::set_global_default(subscriber).is_ok() {
        let _ = LOGGING_INITIALIZED.set(());
        tracing::info!(target: "walletkit::logger", "WalletKit logging initialized");
    }
}
