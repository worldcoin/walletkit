use std::{
    cell::Cell,
    fmt,
    sync::{Arc, Mutex, OnceLock},
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

thread_local! {
    /// Prevents recursive logger callback re-entry on the same thread.
    static IN_FOREIGN_LOGGER_CALLBACK: Cell<bool> = const { Cell::new(false) };
}

struct CallbackGuard<'a>(&'a Cell<bool>);

impl Drop for CallbackGuard<'_> {
    fn drop(&mut self) {
        self.0.set(false);
    }
}

// `ForeignLoggerLayer::on_event` is called synchronously by the tracing subscriber.
// Inside that path we invoke the foreign callback `Logger::log` over FFI.
//
// On some platforms, the host logger may itself emit logs while handling that callback
// (for example through other logging bridges). Those logs are routed back into tracing,
// which re-enters `on_event` before the first call has returned. Without a guard this
// creates unbounded recursion (`on_event -> Logger::log -> on_event -> ...`) and can
// crash the app at launch with a stack overflow / re-entrancy failure.
//
// We use a thread-local flag because this recursion happens on the same thread as the
// synchronous callback. If we detect nested entry, we intentionally drop that nested
// event to preserve process safety and keep the original log flow moving.
fn with_foreign_logger_callback_guard(f: impl FnOnce()) {
    IN_FOREIGN_LOGGER_CALLBACK.with(|in_callback| {
        if in_callback.replace(true) {
            return;
        }

        let _guard = CallbackGuard(in_callback);
        f();
    });
}

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
        with_foreign_logger_callback_guard(|| {
            let callback_lock = logger_callback_lock();
            let _callback_guard = callback_lock
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            logger.log(log_level(*metadata.level()), formatted);
        });
    }
}

static LOGGER_INSTANCE: OnceLock<Arc<dyn Logger>> = OnceLock::new();
static LOGGING_INITIALIZED: OnceLock<()> = OnceLock::new();
static LOGGER_CALLBACK_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn logger_callback_lock() -> &'static Mutex<()> {
    LOGGER_CALLBACK_LOCK.get_or_init(|| Mutex::new(()))
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
// Everything else stays at the baseline (`info`). This keeps
// infrastructure crates (hyper, reqwest, tokio, rustls, …) from
// flooding the FFI logger callback — their debug/trace events fire
// on background threads where UniFFI foreign callbacks can crash.
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
#[uniffi::export]
pub fn init_logging(logger: Arc<dyn Logger>, level: Option<LogLevel>) {
    let _ = LOGGER_INSTANCE.set(logger);
    if LOGGING_INITIALIZED.get().is_some() {
        return;
    }

    let _ = tracing_log::LogTracer::init();

    let filter = build_env_filter(level);
    let subscriber = Registry::default().with(filter).with(ForeignLoggerLayer);

    if tracing::subscriber::set_global_default(subscriber).is_ok() {
        let _ = LOGGING_INITIALIZED.set(());
    }
}
