#!/usr/bin/env python3
"""
Patch generated UniFFI Swift bindings to avoid 1-element vtable arrays.

Why:
- UniFFI generates callback vtables as `[VTableType] = [VTableType(...)]`.
- On newer iOS/Swift toolchains with ASan enabled, this pattern can trigger
  heap-buffer-overflow during static initialization.
- This patch matches the upstream fix from:
  https://github.com/mozilla/uniffi-rs/pull/2821
- This is a temporary downstream workaround until that PR is merged and
  released in UniFFI.
"""

from __future__ import annotations

import argparse
from pathlib import Path


INTERFACES = [
    (
        "AtomicBlobStore",
        "UniffiVTableCallbackInterfaceAtomicBlobStore",
        "uniffi_walletkit_core_fn_init_callback_vtable_atomicblobstore",
    ),
    (
        "DeviceKeystore",
        "UniffiVTableCallbackInterfaceDeviceKeystore",
        "uniffi_walletkit_core_fn_init_callback_vtable_devicekeystore",
    ),
    (
        "Logger",
        "UniffiVTableCallbackInterfaceLogger",
        "uniffi_walletkit_core_fn_init_callback_vtable_logger",
    ),
    (
        "StorageProvider",
        "UniffiVTableCallbackInterfaceStorageProvider",
        "uniffi_walletkit_core_fn_init_callback_vtable_storageprovider",
    ),
]


def patch_interface(text: str, interface: str, vtable_type: str, init_fn: str) -> tuple[str, bool]:
    """Patch a single callback interface block."""
    old_static = f"    static let vtable: [{vtable_type}] = [{vtable_type}("
    new_static = f"    static let vtable: {vtable_type} = {vtable_type}("
    if old_static not in text:
        return text, False
    text = text.replace(old_static, new_static, 1)

    old_tail = (
        "    )]\n"
        "}\n\n"
        f"private func uniffiCallbackInit{interface}() {{\n"
        f"    {init_fn}(UniffiCallbackInterface{interface}.vtable)\n"
        "}\n"
    )
    new_tail = (
        "    )\n"
        "\n"
        "    // Rust stores this pointer for future callback invocations, so it must live\n"
        "    // for the process lifetime (not just for the init function call).\n"
        f"    static let vtablePtr: UnsafePointer<{vtable_type}> = {{\n"
        f"        let ptr = UnsafeMutablePointer<{vtable_type}>.allocate(capacity: 1)\n"
        "        ptr.initialize(to: vtable)\n"
        "        return UnsafePointer(ptr)\n"
        "    }()\n"
        "}\n\n"
        f"private func uniffiCallbackInit{interface}() {{\n"
        f"    {init_fn}(UniffiCallbackInterface{interface}.vtablePtr)\n"
        "}\n"
    )

    if old_tail not in text:
        raise RuntimeError(f"Found vtable static for {interface}, but init function pattern did not match")
    text = text.replace(old_tail, new_tail, 1)
    return text, True


def patch_file(path: Path) -> int:
    text = path.read_text(encoding="utf-8")
    patched_count = 0

    for interface, vtable_type, init_fn in INTERFACES:
        text, patched = patch_interface(text, interface, vtable_type, init_fn)
        if patched:
            patched_count += 1

    if patched_count == 0:
        raise RuntimeError("No UniFFI callback vtable patterns found to patch")
    if patched_count != len(INTERFACES):
        raise RuntimeError(
            f"Partially patched file ({patched_count}/{len(INTERFACES)} interfaces). "
            "Refusing to continue."
        )

    path.write_text(text, encoding="utf-8")
    return patched_count


def main() -> int:
    parser = argparse.ArgumentParser(description="Patch UniFFI Swift callback vtable initialization")
    parser.add_argument("swift_file", help="Path to generated walletkit.swift")
    args = parser.parse_args()

    swift_path = Path(args.swift_file)
    if not swift_path.exists():
        raise FileNotFoundError(f"Swift file not found: {swift_path}")

    patched_count = patch_file(swift_path)
    print(f"Patched {patched_count} UniFFI callback interfaces in {swift_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
