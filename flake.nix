{
  description = "WalletKit development shells";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay.url = "github:oxalica/rust-overlay";
    rust-overlay.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { nixpkgs, flake-utils, rust-overlay, ... }:
    flake-utils.lib.eachSystem [
      "x86_64-linux"
      "aarch64-linux"
      "aarch64-darwin"
      "x86_64-darwin"
    ] (system:
      let
        overlays = [
          (import rust-overlay)
          (final: prev: { nargo = final.callPackage ./nix/nargo.nix { }; })
        ];
        pkgs = import nixpkgs {
          inherit system overlays;
          config = {
            allowUnfree = true;
            android_sdk.accept_license = true;
          };
        };

        rustToolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;

        boltffi = pkgs.rustPlatform.buildRustPackage (finalAttrs: {
          pname = "boltffi_cli";
          version = "0.30.1";

          src = pkgs.fetchCrate {
            inherit (finalAttrs) pname version;
            hash = "sha256-FtD5ZPq0tY+c30VE8H0Qx+VpB/RbdfVUPBUWwTHfgIQ=";
          };

          cargoHash = "sha256-DdfG8Z1joV1ftyIw9UIF0GVYalxMC1gYZtxIWeF8O/E=";

          doCheck = false;
        });
      in
      {
        devShells = {
          default = pkgs.mkShell {
            packages = [
              rustToolchain
              pkgs.curl
              pkgs.git
              pkgs.nargo
            ];
          };

          wasm = import ./nix/wasm.nix { inherit pkgs boltffi; };
        } // pkgs.lib.optionalAttrs (!(pkgs.stdenv.isLinux && pkgs.stdenv.isAarch64)) {
          # The Android NDK has no aarch64-linux prebuilt toolchain
          # (on aarch64 Docker hosts, run the container as linux/amd64).
          android = import ./nix/android.nix { inherit pkgs; };
        };
      });
}
