{ pkgs, boltffi }:
let
  rustToolchain = pkgs.rust-bin.fromRustupToolchainFile ../rust-toolchain.toml;
  llvm = pkgs.llvmPackages;
in
pkgs.mkShell {
  packages = [
    rustToolchain
    llvm.clang-unwrapped
    llvm.bintools-unwrapped
    pkgs.curl
    pkgs.git
    pkgs.nargo
    pkgs.typescript
    pkgs.binaryen
    boltffi
  ];

  # Use unwrapped clang: cc-wrapper injects host hardening flags that are invalid for wasm.
  CC_wasm32_unknown_unknown = "${llvm.clang-unwrapped}/bin/clang";
  AR_wasm32_unknown_unknown = "${llvm.bintools-unwrapped}/bin/llvm-ar";

  shellHook = ''
    echo "WalletKit wasm dev shell"
    echo "  target: wasm32-unknown-unknown"
    echo "  clang: $CC_wasm32_unknown_unknown"
    echo "  boltffi: $(boltffi --version)"
    echo ""
    echo "Build with: boltffi pack wasm --release --cargo-arg=--locked --cargo-arg=--no-default-features --cargo-arg=--features=boltffi-wasm"
  '';
}
