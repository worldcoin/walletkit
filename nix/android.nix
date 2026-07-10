{ pkgs }:
let
  androidApiLevel = "23";
  androidPackages = pkgs.androidenv.composeAndroidPackages {
    platformVersions = [ androidApiLevel ];
    includeNDK = true;
    ndkVersion = "27.2.12479018";
  };
  androidNdkPackage = androidPackages.ndk-bundle;
  # These paths reach into the internal layout of the nixpkgs androidenv derivation
  # (there is no stable API for them). Pinned via flake.lock, but expect them to be
  # the first thing to break on a `nix flake update`.
  androidNdkHome = "${androidNdkPackage}/libexec/android-sdk/ndk-bundle";
  androidToolchainPlatform = if pkgs.stdenv.isDarwin then "darwin-x86_64" else "linux-x86_64";
  androidToolchainBin = "${androidNdkHome}/toolchains/llvm/prebuilt/${androidToolchainPlatform}/bin";

  androidClang = "${androidToolchainBin}/aarch64-linux-android${androidApiLevel}-clang";
  androidClangxx = "${androidToolchainBin}/aarch64-linux-android${androidApiLevel}-clang++";
  androidI686Clang = "${androidToolchainBin}/i686-linux-android${androidApiLevel}-clang";
  androidI686Clangxx = "${androidToolchainBin}/i686-linux-android${androidApiLevel}-clang++";
  androidArmv7Clang = "${androidToolchainBin}/armv7a-linux-androideabi${androidApiLevel}-clang";
  androidArmv7Clangxx = "${androidToolchainBin}/armv7a-linux-androideabi${androidApiLevel}-clang++";
  androidX8664Clang = "${androidToolchainBin}/x86_64-linux-android${androidApiLevel}-clang";
  androidX8664Clangxx = "${androidToolchainBin}/x86_64-linux-android${androidApiLevel}-clang++";

  rustToolchain = pkgs.rust-bin.fromRustupToolchainFile ../rust-toolchain.toml;
in
pkgs.mkShell {
  packages = [
    rustToolchain
    androidNdkPackage
    pkgs.curl
    pkgs.git
    pkgs.jdk17
    pkgs.nargo
  ];

  ANDROID_API_LEVEL = androidApiLevel;
  ANDROID_NDK_HOME = androidNdkHome;
  ANDROID_NDK_ROOT = androidNdkHome;
  NDK_HOME = androidNdkHome;

  # Target rustflags live in .cargo/config.toml — a CARGO_TARGET_*_RUSTFLAGS
  # env var here would replace them, not merge.
  CC_aarch64_linux_android = androidClang;
  CXX_aarch64_linux_android = androidClangxx;
  AR_aarch64_linux_android = "${androidToolchainBin}/llvm-ar";
  RANLIB_aarch64_linux_android = "${androidToolchainBin}/llvm-ranlib";
  CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER = androidClang;

  CC_i686_linux_android = androidI686Clang;
  CXX_i686_linux_android = androidI686Clangxx;
  AR_i686_linux_android = "${androidToolchainBin}/llvm-ar";
  RANLIB_i686_linux_android = "${androidToolchainBin}/llvm-ranlib";
  CARGO_TARGET_I686_LINUX_ANDROID_LINKER = androidI686Clang;

  CC_armv7_linux_androideabi = androidArmv7Clang;
  CXX_armv7_linux_androideabi = androidArmv7Clangxx;
  AR_armv7_linux_androideabi = "${androidToolchainBin}/llvm-ar";
  RANLIB_armv7_linux_androideabi = "${androidToolchainBin}/llvm-ranlib";
  CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER = androidArmv7Clang;

  CC_x86_64_linux_android = androidX8664Clang;
  CXX_x86_64_linux_android = androidX8664Clangxx;
  AR_x86_64_linux_android = "${androidToolchainBin}/llvm-ar";
  RANLIB_x86_64_linux_android = "${androidToolchainBin}/llvm-ranlib";
  CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER = androidX8664Clang;

  shellHook = ''
    echo "WalletKit Android dev shell"
    echo "  targets: aarch64-linux-android, armv7-linux-androideabi, i686-linux-android, x86_64-linux-android (API $ANDROID_API_LEVEL)"
    echo "  ndk:    $ANDROID_NDK_HOME"
    echo ""
    echo "Build with: cargo build -p walletkit --release --target aarch64-linux-android --features compress-zkeys,embed-zkeys,v3"
  '';
}
