# Logging

WalletKit logs through `tracing`. To send those logs to your app's logging system,
implement the `Logger` interface and pass it to `init_logging` once, at app
startup.

`Logger` has one method, `log(level, message)`. The level is one of `Trace`,
`Debug`, `Info`, `Warn`, and `Error`, so your app can map it to `os_log`, Android
`Log`, Crashlytics, Datadog, or any other sink. Each message starts with the name
of the module that logged it, and WalletKit redacts hex secrets from it before
your logger receives it.

On iOS and Android, WalletKit calls `log` from its own background thread, so your
logger must be safe to call from any thread.

`init_logging` behaves as follows:

- Its `level` argument sets the minimum level. At `Trace` or `Debug`, the level
  applies only to WalletKit and its direct dependencies, and other crates log at
  `Info` and above. At `Info`, `Warn`, or `Error`, the level applies to every
  crate. If you pass no level, the minimum is `Info`.
- If the `RUST_LOG` environment variable is set, it takes precedence over `level`.
- Only the first call takes effect; later calls do nothing.

To check that your logger receives messages, call `emit_log(level, message)`.

## Rust

```rust
use std::sync::Arc;
use walletkit::logger::{init_logging, LogLevel, Logger};

struct MyLogger;

impl Logger for MyLogger {
    fn log(&self, level: LogLevel, message: String) {
        println!("[{level:?}] {message}");
    }
}

init_logging(Arc::new(MyLogger), Some(LogLevel::Debug));
```

## Swift

In this example, `Log` stands for your app's logger.

```swift
import WalletKit

final class WalletKitLoggerBridge: WalletKit.Logger {
    static let shared = WalletKitLoggerBridge()

    func log(level: WalletKit.LogLevel, message: String) {
        switch level {
        case .trace, .debug:
            Log.debug(message)
        case .info:
            Log.info(message)
        case .warn:
            Log.warn(message)
        case .error:
            Log.error(message)
        @unknown default:
            Log.error(message)
        }
    }
}

public func setupWalletKitLogging() {
    WalletKit.initLogging(logger: WalletKitLoggerBridge.shared, level: .debug)
}
```

## Kotlin

```kotlin
import android.util.Log
import uniffi.walletkit_core.LogLevel
import uniffi.walletkit_core.Logger
import uniffi.walletkit_core.initLogging

class WalletKitLoggerBridge : Logger {
    override fun log(level: LogLevel, message: String) {
        when (level) {
            LogLevel.TRACE, LogLevel.DEBUG -> Log.d("WalletKit", message)
            LogLevel.INFO -> Log.i("WalletKit", message)
            LogLevel.WARN -> Log.w("WalletKit", message)
            LogLevel.ERROR -> Log.e("WalletKit", message)
        }
    }
}

fun setupWalletKitLogging() {
    initLogging(WalletKitLoggerBridge(), LogLevel.DEBUG)
}
```

## Browser

The browser package has no `Logger`. WalletKit writes its warnings and errors to
the worker's console, and `emitLog` writes through the same path.
