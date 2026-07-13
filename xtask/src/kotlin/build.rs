//! Android library and Kotlin binding generation.

use std::path::{Path, PathBuf};

use eyre::{bail, Result, WrapErr as _};
use xshell::{cmd, Shell};

const DEFAULT_CARGO_FEATURES: &str = "compress-zkeys,embed-zkeys,v3";
const JNI_LIBS_DIR: &str = "kotlin/walletkit/src/main/jniLibs";
const KOTLIN_SOURCE_DIR: &str = "kotlin/walletkit/src/main/java";

struct AndroidTarget {
    rust_name: &'static str,
    abi_name: &'static str,
}

const ANDROID_TARGETS: [AndroidTarget; 4] = [
    AndroidTarget {
        rust_name: "aarch64-linux-android",
        abi_name: "arm64-v8a",
    },
    AndroidTarget {
        rust_name: "armv7-linux-androideabi",
        abi_name: "armeabi-v7a",
    },
    AndroidTarget {
        rust_name: "x86_64-linux-android",
        abi_name: "x86_64",
    },
    AndroidTarget {
        rust_name: "i686-linux-android",
        abi_name: "x86",
    },
];

pub(super) fn run(sh: &Shell, artifacts_dir: Option<&Path>) -> Result<()> {
    if artifacts_dir.is_none() {
        ensure_android_toolchain(sh)?;
        build_native_libraries(sh)?;
    }

    copy_native_libraries(sh, artifacts_dir)?;
    generate_bindings(sh)?;

    println!("Kotlin/Android build complete.");
    Ok(())
}

fn ensure_android_toolchain(sh: &Shell) -> Result<()> {
    let linker_is_configured = sh
        .var_os("CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER")
        .is_some_and(|linker| !linker.is_empty());

    if !linker_is_configured {
        bail!(
            "Android cross-compilation environment is not configured.\n\
             Run inside the Nix devshell:\n  \
             nix develop .#android --command cargo xtask kotlin build\n\
             Or use Docker without Nix:\n  \
             nix/docker.sh develop .#android --command cargo xtask kotlin build"
        );
    }

    Ok(())
}

fn build_native_libraries(sh: &Shell) -> Result<()> {
    let features = cargo_features(sh);
    println!("Building WalletKit for Android...");

    for target in &ANDROID_TARGETS {
        let rust_target = target.rust_name;
        println!("Building {rust_target}...");
        cmd!(
            sh,
            "cargo build -p walletkit --release --locked --target {rust_target} --features {features}"
        )
        .run()
        .wrap_err_with(|| format!("failed to build WalletKit for {rust_target}"))?;
    }

    Ok(())
}

fn cargo_features(sh: &Shell) -> String {
    sh.var("WALLETKIT_CARGO_FEATURES")
        .ok()
        .filter(|features| !features.is_empty())
        .unwrap_or_else(|| DEFAULT_CARGO_FEATURES.to_owned())
}

fn copy_native_libraries(sh: &Shell, artifacts_dir: Option<&Path>) -> Result<()> {
    println!("Copying Android native libraries...");

    for target in &ANDROID_TARGETS {
        let source = native_library_source(target, artifacts_dir);
        let destination_dir = Path::new(JNI_LIBS_DIR).join(target.abi_name);
        let destination = destination_dir.join("libwalletkit.so");

        sh.create_dir(&destination_dir)?;
        sh.copy_file(&source, &destination).wrap_err_with(|| {
            format!(
                "failed to copy {} to {}",
                source.display(),
                destination.display()
            )
        })?;
    }

    Ok(())
}

fn native_library_source(
    target: &AndroidTarget,
    artifacts_dir: Option<&Path>,
) -> PathBuf {
    artifacts_dir.map_or_else(
        || {
            Path::new("target")
                .join(target.rust_name)
                .join("release/libwalletkit.so")
        },
        |directory| {
            directory
                .join(format!("android-{}", target.rust_name))
                .join("libwalletkit.so")
        },
    )
}

fn generate_bindings(sh: &Shell) -> Result<()> {
    let library = Path::new(JNI_LIBS_DIR)
        .join("arm64-v8a")
        .join("libwalletkit.so");

    println!("Generating Kotlin bindings...");
    cmd!(
        sh,
        "cargo run -p uniffi-bindgen --locked -- generate {library} --library --language kotlin --no-format --out-dir {KOTLIN_SOURCE_DIR}"
    )
    .run()
    .wrap_err("failed to generate Kotlin bindings")
}
