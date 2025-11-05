use std::sync::{Arc, OnceLock};

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

/// A logger that forwards log messages to a user-provided `Logger` implementation.
///
/// This struct implements the `log::Log` trait and integrates with the Rust `log` crate.
struct ForeignLogger;

impl log::Log for ForeignLogger {
    /// Determines if a log message with the specified metadata should be logged.
    ///
    /// This implementation logs all messages. Modify this method to implement log level filtering.
    ///
    /// # Arguments
    ///
    /// * `_metadata` - Metadata about the log message.
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        // Currently, we log all messages. Adjust this if you need to filter messages.
        true
    }

    /// Logs a record.
    ///
    /// This method is called by the `log` crate when a log message needs to be logged.
    /// It forwards the log message to the user-provided `Logger` implementation if available.
    ///
    /// # Arguments
    ///
    /// * `record` - The log record containing the message and metadata.
    fn log(&self, record: &log::Record) {
        // Determine if the record originates from the "walletkit" module.
        let is_record_from_walletkit = record
            .module_path()
            .is_some_and(|module_path| module_path.starts_with("walletkit"));

        // Determine if the log level is Debug or Trace.
        let is_debug_or_trace_level =
            record.level() == log::Level::Debug || record.level() == log::Level::Trace;

        // Skip logging Debug or Trace level messages that are not from the "walletkit" module.
        if is_debug_or_trace_level && !is_record_from_walletkit {
            return;
        }

        // Forward the log message to the user-provided logger if available.
        if let Some(logger) = LOGGER_INSTANCE.get() {
            let level = log_level(record.level());
            let message = format!("{}", record.args());
            logger.log(level, message);
        } else {
            // Handle the case when the logger is not set.
            eprintln!("Logger not set: {}", record.args());
        }
    }

    /// Flushes any buffered records.
    ///
    /// This implementation does nothing because buffering is not used.
    fn flush(&self) {}
}

/// Converts a `log::Level` to a `LogLevel`.
///
/// This function maps the log levels from the `log` crate to your own `LogLevel` enum.
///
/// # Arguments
///
/// * `level` - The `log::Level` to convert.
///
/// # Returns
///
/// A corresponding `LogLevel`.
const fn log_level(level: log::Level) -> LogLevel {
    match level {
        log::Level::Error => LogLevel::Error,
        log::Level::Warn => LogLevel::Warn,
        log::Level::Info => LogLevel::Info,
        log::Level::Debug => LogLevel::Debug,
        log::Level::Trace => LogLevel::Trace,
    }
}

/// A global instance of the user-provided logger.
///
/// This static variable holds the logger provided by the user and is accessed by `ForeignLogger` to forward log messages.
static LOGGER_INSTANCE: OnceLock<Arc<dyn Logger>> = OnceLock::new();

/// Sets the global logger.
///
/// This function allows you to provide your own implementation of the `Logger` trait.
/// It initializes the logging system and should be called before any logging occurs.
///
/// # Arguments
///
/// * `logger` - An `Arc` containing your logger implementation.
///
/// # Panics
///
/// Panics if the logger has already been set.
///
/// # Note
///
/// If the logger has already been set, this function will print a message and do nothing.
#[uniffi::export]
pub fn set_logger(logger: Arc<dyn Logger>) {
    match LOGGER_INSTANCE.set(logger) {
        Ok(()) => (),
        Err(_) => println!("Logger already set"),
    }

    // Initialize the logger system.
    if let Err(e) = init_logger() {
        eprintln!("Failed to set logger: {e}");
    }
}

/// Initializes the logger system.
///
/// This function sets up the global logger with the `ForeignLogger` implementation and sets the maximum log level.
///
/// # Returns
///
/// A `Result` indicating success or failure.
///
/// # Errors
///
/// Returns a `log::SetLoggerError` if the logger could not be set (e.g., if a logger was already set).
fn init_logger() -> Result<(), log::SetLoggerError> {
    static LOGGER: ForeignLogger = ForeignLogger;
    log::set_logger(&LOGGER)?;
    log::set_max_level(log::LevelFilter::Trace);
    Ok(())
}
