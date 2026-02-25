use std::sync::{Arc, OnceLock};

use tracing_core::{Event, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{EnvFilter, Layer};

/// Trait representing a logger that can log messages at various levels.
///
/// This trait should be implemented by any logger that wants to receive log messages.
/// It is exported via `UniFFI` for use in foreign languages.
///
/// # Examples
///
/// Implementing the `Logger` trait:
///
/// ```rust
/// use walletkit_core::logger::{Logger, LogLevel};
///
/// struct MyLogger;
///
/// impl Logger for MyLogger {
///     fn log(&self, level: LogLevel, message: String) {
///         println!("[{:?}] {}", level, message);
///     }
/// }
/// ```
///
/// ## Swift
///
/// ```swift
/// class WalletKitLoggerBridge: WalletKit.Logger {
///     static let shared = WalletKitLoggerBridge()
///
///     func log(level: WalletKit.LogLevel, message: String) {
///         Log.log(level.toCoreLevel(), message)
///     }
/// }
///
/// public func setupWalletKitLogger() {
///     WalletKit.setLogger(logger: WalletKitLoggerBridge.shared)
/// }
/// ```
///
/// ### In app delegate
///
/// ```swift
/// setupWalletKitLogger() // Call this only once!!!
/// ```
#[uniffi::export(with_foreign)]
pub trait Logger: Sync + Send {
    /// Logs a message at the specified log level.
    ///
    /// # Arguments
    ///
    /// * `level` - The severity level of the log message.
    /// * `message` - The log message to be recorded.
    fn log(&self, level: LogLevel, message: String);
}

/// Enumeration of possible log levels.
///
/// This enum represents the severity levels that can be used when logging messages.
#[derive(Debug, Clone, uniffi::Enum)]
pub enum LogLevel {
    /// Designates very low priority, often extremely detailed messages.
    Trace,
    /// Designates lower priority debugging information.
    Debug,
    /// Designates informational messages that highlight the progress of the application.
    Info,
    /// Designates potentially harmful situations.
    Warn,
    /// Designates error events that might still allow the application to continue running.
    Error,
}

/// A global instance of the user-provided logger.
///
/// This static variable holds the logger provided by the user and is accessed
/// by the tracing layer to forward log messages.
static LOGGER_INSTANCE: OnceLock<Arc<dyn Logger>> = OnceLock::new();

/// A `tracing` [`Layer`] that forwards events to the foreign [`Logger`] callback.
///
/// When no foreign logger is registered via [`set_logger`], this layer is a
/// no-op and events fall through to the default `fmt` layer which writes to
/// stdout/stderr.
struct ForeignLoggerLayer;

impl<S: Subscriber> Layer<S> for ForeignLoggerLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let Some(logger) = LOGGER_INSTANCE.get() else {
            return;
        };

        // Only forward walletkit-originating events at Debug/Trace level.
        let meta = event.metadata();
        let level = meta.level();
        let is_walletkit = meta
            .module_path()
            .is_some_and(|m| m.starts_with("walletkit"));

        if (*level == tracing::Level::DEBUG || *level == tracing::Level::TRACE)
            && !is_walletkit
        {
            return;
        }

        // Format the event fields into a single message string.
        let mut visitor = MessageVisitor(String::new());
        event.record(&mut visitor);

        logger.log(to_log_level(*level), visitor.0);
    }
}

/// Visitor that collects event fields into a formatted string.
struct MessageVisitor(String);

impl tracing::field::Visit for MessageVisitor {
    fn record_debug(
        &mut self,
        field: &tracing::field::Field,
        value: &dyn std::fmt::Debug,
    ) {
        if field.name() == "message" {
            self.0 = format!("{value:?}");
        } else if self.0.is_empty() {
            self.0 = format!("{} = {value:?}", field.name());
        } else {
            self.0 = format!("{}, {} = {value:?}", self.0, field.name());
        }
    }
}

/// Converts a [`tracing::Level`] to a [`LogLevel`].
const fn to_log_level(level: tracing::Level) -> LogLevel {
    match level {
        tracing::Level::ERROR => LogLevel::Error,
        tracing::Level::WARN => LogLevel::Warn,
        tracing::Level::INFO => LogLevel::Info,
        tracing::Level::DEBUG => LogLevel::Debug,
        tracing::Level::TRACE => LogLevel::Trace,
    }
}

/// Sets the global logger and initialises the tracing subscriber.
///
/// When a foreign [`Logger`] is provided, **all** tracing events are forwarded
/// to it (subject to level/module filtering identical to the previous `log`
/// crate behaviour).  The default `fmt` subscriber is still installed so that
/// events are printed to stdout when no foreign logger has been registered.
///
/// # Arguments
///
/// * `logger` - An `Arc` containing your logger implementation.
///
/// # Note
///
/// If the logger has already been set, this function will print a message and
/// do nothing.
#[uniffi::export]
pub fn set_logger(logger: Arc<dyn Logger>) {
    if LOGGER_INSTANCE.set(logger).is_err() {
        eprintln!("Logger already set");
        return;
    }

    init_tracing();
}

/// Initialises the default tracing subscriber with both `fmt` (stdout) and
/// the [`ForeignLoggerLayer`].
///
/// This is safe to call multiple times – only the first call installs the
/// global subscriber.
fn init_tracing() {
    // Build an EnvFilter: honour RUST_LOG if set, otherwise default to
    // info-level for walletkit crates plus warn for everything else.
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new("walletkit=debug,walletkit_core=debug,warn")
    });

    let subscriber = tracing_subscriber::registry()
        .with(filter)
        .with(ForeignLoggerLayer)
        .with(tracing_subscriber::fmt::layer().with_target(true));

    // `try_init` returns Err if a subscriber is already installed – that's OK.
    let _ = tracing::subscriber::set_global_default(subscriber);
}

/// Initialise the default tracing subscriber (stdout only, no foreign logger).
///
/// This is called automatically when the library loads (via `ctor`) so that
/// upstream crates using `tracing` emit output even if the consumer never
/// calls [`set_logger`].
#[cfg(not(test))]
pub(crate) fn init_default_tracing() {
    init_tracing();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_level_conversion_round_trips() {
        assert!(matches!(
            to_log_level(tracing::Level::ERROR),
            LogLevel::Error
        ));
        assert!(matches!(to_log_level(tracing::Level::WARN), LogLevel::Warn));
        assert!(matches!(to_log_level(tracing::Level::INFO), LogLevel::Info));
        assert!(matches!(
            to_log_level(tracing::Level::DEBUG),
            LogLevel::Debug
        ));
        assert!(matches!(
            to_log_level(tracing::Level::TRACE),
            LogLevel::Trace
        ));
    }
}
