# Host-mediated UniFFI experiment

This experiment proves that a base Rust library can compose with multiple **separately compiled** Rust implementation libraries without using a Rust-native trait ABI across binaries.

## Architecture

- `text-core`: shared request/response models, validation, and JSON helpers.
- `switchboard`: base orchestrator `cdylib` exporting a synchronous UniFFI trait with foreign implementations.
- `shouty`: implementation `cdylib` whose `ShoutyProcessor` exposes an async UniFFI API and uppercases text.
- `mirror`: implementation `cdylib` whose `MirrorProcessor` exposes an async UniFFI API and reverses text.
- `host-python`: Python harness that imports all three generated bindings, adapts the async processor methods into the synchronous `ProcessorDriver` trait, and selects the implementation at runtime.

The host mediates composition:

1. Python creates `Switchboard`, `ShoutyProcessor`, and `MirrorProcessor`.
2. Python wraps the concrete processors in `ProcessorDriver` adapter objects.
3. `Switchboard` stores the adapters behind `Arc<dyn ProcessorDriver>`.
4. At runtime, Python picks which processor name to call.
5. `Switchboard::process_with` uses `tokio::task::spawn_blocking` to call the blocking adapter.
6. Each Python adapter uses `asyncio.run_coroutine_threadsafe` to bridge into the processor's async UniFFI method.
7. The processor performs genuine Tokio async work before returning its JSON response.

## Build and generate Python bindings

From the repository root:

```bash
./experiment/generate_python_bindings.sh
```

That script:

- builds the Rust experiment workspace in release mode
- generates Python bindings for `switchboard`, `shouty`, and `mirror`
- copies each native library beside its generated Python module for easy loading

## Run the demo

```bash
python3 experiment/host-python/main.py shouty "hello world"
python3 experiment/host-python/main.py mirror "hello world"
```

Expected output:

```json
{"processor":"shouty","output":"HELLO WORLD"}
{"processor":"mirror","output":"dlrow olleh"}
```

## Notes

- The Rust-to-host boundary uses JSON `String` payloads intentionally, to keep the experiment focused on host-mediated composition across separate binaries.
- `text-core` is reused as a **source dependency** by all Rust crates, not as a cross-binary ABI.
- `switchboard::ProcessorDriver` stays synchronous so Python can implement the UniFFI foreign trait with adapters.
- `shouty` and `mirror` keep their own async APIs, allowing real async work without blocking Tokio worker threads in `switchboard`.
