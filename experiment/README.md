# Host-mediated UniFFI experiment

This experiment proves that a base Rust library can compose with multiple **separately compiled** Rust implementation libraries without using a Rust-native trait ABI across binaries.

## Architecture

- `text-core`: shared request/response models, validation, and JSON helpers.
- `switchboard`: base orchestrator `cdylib` exporting a UniFFI **foreign trait**.
- `shouty`: implementation `cdylib` that uppercases text.
- `mirror`: implementation `cdylib` that reverses text.
- `host-python`: Python harness that imports all three generated bindings, adapts concrete processors to the `switchboard.ProcessorDriver` foreign trait, and selects the implementation at runtime.

The host mediates composition:

1. Python creates `Switchboard`, `ShoutyProcessor`, and `MirrorProcessor`.
2. Python implements `switchboard.ProcessorDriver` adapters.
3. `Switchboard` stores those adapters behind `Arc<dyn ProcessorDriver>`.
4. At runtime, Python picks which processor name to call.
5. `Switchboard` invokes the host callback, and the host forwards to the chosen Rust component.

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
- Async is intentionally left as a future follow-up once the synchronous architecture is proven.
