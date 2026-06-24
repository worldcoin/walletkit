{ pkgs }:
let
  lib = pkgs.lib;
  rustToolchain = pkgs.rust-bin.fromRustupToolchainFile ../rust-toolchain.toml;

  systemTool = tool: pkgs.writeShellScriptBin tool ''
    exec /usr/bin/${tool} "$@"
  '';

  appleTools = pkgs.symlinkJoin {
    name = "walletkit-apple-tools";
    paths = map systemTool [
      "xcodebuild"
      "xcrun"
      "lipo"
      "swift"
      "swiftc"
    ];
  };

  xcrunTool = name: sdk: tool: pkgs.writeShellScriptBin name ''
    exec /usr/bin/xcrun --sdk ${sdk} ${tool} "$@"
  '';

  iphoneosClang = xcrunTool "walletkit-iphoneos-clang" "iphoneos" "clang";
  iphoneosClangxx = xcrunTool "walletkit-iphoneos-clangxx" "iphoneos" "clang++";
  iphoneosAr = xcrunTool "walletkit-iphoneos-ar" "iphoneos" "ar";
  iphoneosRanlib = xcrunTool "walletkit-iphoneos-ranlib" "iphoneos" "ranlib";

  iphonesimulatorClang = xcrunTool "walletkit-iphonesimulator-clang" "iphonesimulator" "clang";
  iphonesimulatorClangxx = xcrunTool "walletkit-iphonesimulator-clangxx" "iphonesimulator" "clang++";
  iphonesimulatorAr = xcrunTool "walletkit-iphonesimulator-ar" "iphonesimulator" "ar";
  iphonesimulatorRanlib = xcrunTool "walletkit-iphonesimulator-ranlib" "iphonesimulator" "ranlib";
in
assert lib.assertMsg pkgs.stdenv.isDarwin "WalletKit Swift dev shell requires macOS with Xcode installed";
pkgs.mkShell {
  packages = [
    appleTools
    rustToolchain
    pkgs.cmake
    pkgs.curl
    pkgs.git
    pkgs.ninja
    pkgs.rsync
    pkgs.swiftlint
    pkgs.zip
  ];

  IPHONEOS_DEPLOYMENT_TARGET = "13.0";
  IPHONESIMULATOR_DEPLOYMENT_TARGET = "13.0";

  CC_aarch64_apple_ios = "${iphoneosClang}/bin/walletkit-iphoneos-clang";
  CXX_aarch64_apple_ios = "${iphoneosClangxx}/bin/walletkit-iphoneos-clangxx";
  AR_aarch64_apple_ios = "${iphoneosAr}/bin/walletkit-iphoneos-ar";
  RANLIB_aarch64_apple_ios = "${iphoneosRanlib}/bin/walletkit-iphoneos-ranlib";
  CARGO_TARGET_AARCH64_APPLE_IOS_LINKER = "${iphoneosClang}/bin/walletkit-iphoneos-clang";

  CC_aarch64_apple_ios_sim = "${iphonesimulatorClang}/bin/walletkit-iphonesimulator-clang";
  CXX_aarch64_apple_ios_sim = "${iphonesimulatorClangxx}/bin/walletkit-iphonesimulator-clangxx";
  AR_aarch64_apple_ios_sim = "${iphonesimulatorAr}/bin/walletkit-iphonesimulator-ar";
  RANLIB_aarch64_apple_ios_sim = "${iphonesimulatorRanlib}/bin/walletkit-iphonesimulator-ranlib";
  CARGO_TARGET_AARCH64_APPLE_IOS_SIM_LINKER = "${iphonesimulatorClang}/bin/walletkit-iphonesimulator-clang";

  CC_x86_64_apple_ios = "${iphonesimulatorClang}/bin/walletkit-iphonesimulator-clang";
  CXX_x86_64_apple_ios = "${iphonesimulatorClangxx}/bin/walletkit-iphonesimulator-clangxx";
  AR_x86_64_apple_ios = "${iphonesimulatorAr}/bin/walletkit-iphonesimulator-ar";
  RANLIB_x86_64_apple_ios = "${iphonesimulatorRanlib}/bin/walletkit-iphonesimulator-ranlib";
  CARGO_TARGET_X86_64_APPLE_IOS_LINKER = "${iphonesimulatorClang}/bin/walletkit-iphonesimulator-clang";

  shellHook = ''
    export PATH="${appleTools}/bin:$PATH"
    unset SDKROOT

    if [ -d /Applications/Xcode.app/Contents/Developer ] \
      && [ ! -d "''${DEVELOPER_DIR:-}/Platforms/iPhoneSimulator.platform" ]; then
      export DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer
    fi

    echo "WalletKit Swift dev shell"
    echo "  requires: host Xcode with iOS SDKs installed"
    echo "  developer dir: ''${DEVELOPER_DIR:-$(/usr/bin/xcode-select -p 2>/dev/null || echo unknown)}"
    echo "  targets:       aarch64-apple-ios, aarch64-apple-ios-sim, x86_64-apple-ios"
    echo ""
    echo "Build with: ./swift/build_swift.sh"
    echo "Test with:  ./swift/test_swift.sh"
  '';
}
