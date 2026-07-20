//! Kotlin/JVM foreign binding tests.

use std::path::{Path, PathBuf};

use eyre::{bail, Result, WrapErr as _};
use xshell::{cmd, Shell};

const CARGO_FEATURES: &str = "compress-zkeys,embed-zkeys,v3";
const JAVA_SOURCE_DIR: &str = "kotlin/walletkit/src/main/java";
const HOST_LIBRARIES_DIR: &str = "kotlin/libs";
const TEST_RESULTS_DIR: &str = "kotlin/walletkit-tests/build/test-results/test";

pub(super) fn run(sh: &Shell) -> Result<()> {
    ensure_java_home(sh);
    sh.remove_path(TEST_RESULTS_DIR)?;

    build_host_bindings(sh)?;
    run_gradle_tests(sh)?;

    println!("Kotlin test results: {TEST_RESULTS_DIR}");
    Ok(())
}

fn build_host_bindings(sh: &Shell) -> Result<()> {
    sh.remove_path(JAVA_SOURCE_DIR)?;
    sh.remove_path(HOST_LIBRARIES_DIR)?;
    sh.create_dir(JAVA_SOURCE_DIR)?;
    sh.create_dir(HOST_LIBRARIES_DIR)?;

    println!("Building WalletKit for the host platform...");
    cmd!(
        sh,
        "cargo build -p walletkit --release --locked --features {CARGO_FEATURES}"
    )
    .run()
    .wrap_err("failed to build the host WalletKit library")?;

    let library = host_library()?;
    sh.copy_file(&library, HOST_LIBRARIES_DIR)
        .wrap_err_with(|| format!("failed to copy {}", library.display()))?;

    println!("Generating Kotlin test bindings...");
    cmd!(
        sh,
        "cargo run -p uniffi-bindgen --locked -- generate {library} --language kotlin --library --crate walletkit_core --out-dir {JAVA_SOURCE_DIR}"
    )
    .run()
    .wrap_err("failed to generate Kotlin test bindings")
}

fn host_library() -> Result<PathBuf> {
    let file_name = if cfg!(target_os = "macos") {
        "libwalletkit.dylib"
    } else if cfg!(target_os = "linux") {
        "libwalletkit.so"
    } else {
        bail!("Kotlin/JVM foreign binding tests support only macOS and Linux hosts");
    };

    Ok(Path::new("target/release").join(file_name))
}

fn run_gradle_tests(sh: &Shell) -> Result<()> {
    if !sh.path_exists("kotlin/gradlew") {
        bail!("the tracked Kotlin Gradle wrapper is missing: kotlin/gradlew");
    }

    println!("Running Kotlin/JVM tests...");
    let _kotlin_dir = sh.push_dir("kotlin");
    cmd!(
        sh,
        "./gradlew --no-daemon walletkit-tests:test --info --continue"
    )
    .run()
    .wrap_err("Kotlin/JVM tests failed")
}

fn ensure_java_home(sh: &Shell) {
    let java_home_is_set = sh
        .var_os("JAVA_HOME")
        .is_some_and(|java_home| !java_home.is_empty());
    if java_home_is_set {
        return;
    }

    if let Some(java_home) = homebrew_java_home(sh) {
        sh.set_var("JAVA_HOME", java_home);
        println!("Detected JAVA_HOME: {java_home}");
        return;
    }

    let settings = cmd!(sh, "java -XshowSettings:properties -version")
        .quiet()
        .read_stderr();

    let Ok(settings) = settings else {
        eprintln!("warning: JAVA_HOME is unset and Java was not found in PATH");
        return;
    };

    let java_home = settings
        .lines()
        .map(str::trim)
        .find_map(|line| line.strip_prefix("java.home = "));

    if let Some(java_home) = java_home {
        sh.set_var("JAVA_HOME", java_home);
        println!("Detected JAVA_HOME: {java_home}");
    } else {
        eprintln!("warning: JAVA_HOME is unset and could not be inferred from Java");
    }
}

fn homebrew_java_home(sh: &Shell) -> Option<&'static str> {
    const CANDIDATES: [&str; 2] = [
        "/opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home",
        "/usr/local/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home",
    ];

    cfg!(target_os = "macos")
        .then(|| {
            CANDIDATES
                .into_iter()
                .find(|candidate| sh.path_exists(candidate))
        })
        .flatten()
}
