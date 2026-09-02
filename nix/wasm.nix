{ pkgs }:
let
  rustToolchain = pkgs.rust-bin.fromRustupToolchainFile ../rust-toolchain.toml;
  llvm = pkgs.llvmPackages;
  wasmBindgenCli = pkgs.rustPlatform.buildRustPackage rec {
    pname = "wasm-bindgen-cli";
    version = "0.2.126";
    src = pkgs.fetchurl {
      name = "${pname}-${version}.tar.gz";
      url = "https://static.crates.io/crates/${pname}/${pname}-${version}.crate";
      hash = "sha256-ji6/bu+Hw05mI0fx3d++pUEwS7cpRxHtLCrNh0bMW1A=";
    };
    cargoHash = "sha256-VucqkXbCi4qtQzY/HrXiDnbSURsagPsdNVMn1Tw3UiY=";
    doCheck = false;
  };
  firefoxAvailable = pkgs.lib.meta.availableOn pkgs.stdenv.hostPlatform pkgs.firefox;
in
pkgs.mkShell {
  packages = [
    rustToolchain
    llvm.clang-unwrapped
    llvm.bintools-unwrapped
    wasmBindgenCli
    pkgs.curl
    pkgs.git
    pkgs.nargo
  ]
  ++ pkgs.lib.optionals firefoxAvailable [
    pkgs.firefox
    pkgs.geckodriver
  ];

  # Use unwrapped clang: cc-wrapper injects host hardening flags that are invalid for wasm.
  CC_wasm32_unknown_unknown = "${llvm.clang-unwrapped}/bin/clang";
  AR_wasm32_unknown_unknown = "${llvm.bintools-unwrapped}/bin/llvm-ar";

  shellHook = ''
    echo "WalletKit wasm dev shell"
    echo "  target: wasm32-unknown-unknown"
    echo "  clang: $CC_wasm32_unknown_unknown"
    echo ""
    echo "Build with: cargo build -p walletkit --target wasm32-unknown-unknown"
    echo "Test with:  cargo test -p walletkit-sqlite --target wasm32-unknown-unknown"
  '';
}
