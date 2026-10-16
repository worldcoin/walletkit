# Noir is not packaged in nixpkgs, so we repackage the official prebuilt
# release binaries. The version must match what the provekit crates expect
# (see the provekit_* entries in Cargo.lock, versioned `<noir-version>-alpha.N`).
{ stdenv, lib, fetchurl, autoPatchelfHook }:

let
  artifacts = {
    aarch64-darwin = {
      target = "aarch64-apple-darwin";
      hash = "sha256-K4qTig6uQR0BBRM+seuXsLHxlCA3svQsn6xyRW9emzI=";
    };
    x86_64-darwin = {
      target = "x86_64-apple-darwin";
      hash = "sha256-08tm8/PWpGvXoQ5zUbqzvnksOUwD7fjMEQ+O3nyRX1c=";
    };
    x86_64-linux = {
      target = "x86_64-unknown-linux-gnu";
      hash = "sha256-ZASAQL79VamHFYsRE32POPloj2lttNhJEN0bzwRC+4A=";
    };
    aarch64-linux = {
      target = "aarch64-unknown-linux-gnu";
      hash = "sha256-5iuXAXUfL5vRhnFyS2NEr1mNh0XOjN5V1hzCdiI3GBE=";
    };
  };
  artifact =
    artifacts.${stdenv.hostPlatform.system}
      or (throw "nargo: no prebuilt binary for ${stdenv.hostPlatform.system}");
in stdenv.mkDerivation rec {
  pname = "nargo";
  version = "1.0.0-beta.26";

  src = fetchurl {
    url = "https://github.com/noir-lang/noir/releases/download/v${version}/nargo-${artifact.target}.tar.gz";
    hash = artifact.hash;
  };

  sourceRoot = ".";

  nativeBuildInputs = lib.optionals stdenv.isLinux [ autoPatchelfHook ];
  buildInputs = lib.optionals stdenv.isLinux [ stdenv.cc.cc.lib ];

  installPhase = ''
    runHook preInstall
    install -Dm755 nargo $out/bin/nargo
    runHook postInstall
  '';

  meta = {
    description = "Noir compiler and package manager";
    homepage = "https://noir-lang.org";
    license = with lib.licenses; [ mit asl20 ];
    sourceProvenance = [ lib.sourceTypes.binaryNativeCode ];
    platforms = lib.attrNames artifacts;
    mainProgram = "nargo";
  };
}
