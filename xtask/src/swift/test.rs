//! Swift foreign-binding tests.

use std::path::Path;

use eyre::{bail, Context, Result};
use xshell::{cmd, Shell};

use super::build;

const FRAMEWORK_DIR: &str = "swift/WalletKit.xcframework";
const GENERATED_SOURCES_DIR: &str = "swift/Sources/WalletKit";
const TEST_BUILD_DIR: &str = "swift/tests/.build";
const TEST_SOURCES_DIR: &str = "swift/tests/Sources/WalletKit";
const TESTS_DIR: &str = "swift/tests";

pub(super) fn run(sh: &Shell, skip_build: bool) -> Result<()> {
    ensure_macos()?;

    if !skip_build {
        build::run(sh, None)?;
    }

    ensure_simulator_sdk(sh)?;
    prepare_test_package(sh)?;
    let simulator_id = find_simulator(sh)?;
    prepare_simulator(sh, &simulator_id)?;
    run_tests(sh, &simulator_id)?;

    println!("Swift foreign-binding tests passed.");
    Ok(())
}

fn ensure_macos() -> Result<()> {
    if !cfg!(target_os = "macos") {
        bail!("Swift foreign-binding tests require macOS and Xcode");
    }
    Ok(())
}

fn ensure_simulator_sdk(sh: &Shell) -> Result<()> {
    let sdks = cmd!(sh, "xcodebuild -showsdks")
        .read()
        .context("failed to list installed Xcode SDKs")?;
    if !sdks.contains("iphonesimulator") {
        bail!("no iOS Simulator SDK is installed; available SDKs:\n{sdks}");
    }
    Ok(())
}

fn prepare_test_package(sh: &Shell) -> Result<()> {
    if !sh.path_exists(FRAMEWORK_DIR) {
        bail!(
            "{FRAMEWORK_DIR} is missing; run `cargo xtask swift build` first or omit --skip-build"
        );
    }
    if !sh.path_exists(GENERATED_SOURCES_DIR) {
        bail!(
            "{GENERATED_SOURCES_DIR} is missing; run `cargo xtask swift build` first or omit --skip-build"
        );
    }

    sh.remove_path(TEST_SOURCES_DIR)?;
    sh.create_dir(TEST_SOURCES_DIR)?;
    copy_directory_contents(
        sh,
        Path::new(GENERATED_SOURCES_DIR),
        Path::new(TEST_SOURCES_DIR),
    )?;

    sh.remove_path(TEST_BUILD_DIR)?;
    remove_derived_data(sh)?;
    Ok(())
}

fn copy_directory_contents(
    sh: &Shell,
    source: &Path,
    destination: &Path,
) -> Result<()> {
    for source_path in sh
        .read_dir(source)
        .with_context(|| format!("failed to read {}", source.display()))?
    {
        let file_name = source_path
            .file_name()
            .expect("directory entries must have a file name");
        let destination_path = destination.join(file_name);

        if source_path.is_dir() {
            sh.create_dir(&destination_path)?;
            copy_directory_contents(sh, &source_path, &destination_path)?;
        } else {
            sh.copy_file(&source_path, &destination_path)
                .with_context(|| {
                    format!(
                        "failed to copy {} to {}",
                        source_path.display(),
                        destination_path.display()
                    )
                })?;
        }
    }

    Ok(())
}

fn remove_derived_data(sh: &Shell) -> Result<()> {
    let Some(home) = sh.var_os("HOME") else {
        return Ok(());
    };
    let derived_data = Path::new(&home).join("Library/Developer/Xcode/DerivedData");
    if !derived_data.exists() {
        return Ok(());
    }

    for path in sh
        .read_dir(&derived_data)
        .with_context(|| format!("failed to read {}", derived_data.display()))?
    {
        if path.file_name().is_some_and(|name| {
            name.to_string_lossy()
                .starts_with("WalletKitForeignTestPackage-")
        }) {
            sh.remove_path(path)?;
        }
    }
    Ok(())
}

fn find_simulator(sh: &Shell) -> Result<String> {
    let devices = cmd!(sh, "xcrun simctl list devices available")
        .read()
        .context("failed to list available iOS simulators")?;

    simulator_id(&devices, "iPhone 16")
        .or_else(|| simulator_id(&devices, "iPhone"))
        .ok_or_else(|| eyre::eyre!("no available iPhone simulator was found"))
}

fn simulator_id(devices: &str, preferred_name: &str) -> Option<String> {
    devices
        .lines()
        .filter(|line| line.contains(preferred_name))
        .find_map(|line| {
            line.split(['(', ')'])
                .map(str::trim)
                .find(|value| is_uuid(value))
                .map(str::to_owned)
        })
}

fn is_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

fn prepare_simulator(sh: &Shell, simulator_id: &str) -> Result<()> {
    if !is_ci(sh) {
        println!("Using local simulator without erasing it: {simulator_id}");
        return Ok(());
    }

    println!("Resetting simulator for CI: {simulator_id}");
    let _ = cmd!(sh, "xcrun simctl shutdown {simulator_id}")
        .quiet()
        .run();
    cmd!(sh, "xcrun simctl erase {simulator_id}")
        .run()
        .context("failed to erase iOS simulator")?;
    cmd!(sh, "xcrun simctl boot {simulator_id}")
        .run()
        .context("failed to boot iOS simulator")?;
    cmd!(sh, "xcrun simctl bootstatus {simulator_id} -b")
        .run()
        .context("iOS simulator failed to finish booting")
}

fn is_ci(sh: &Shell) -> bool {
    ["GITHUB_ACTIONS", "CI"].into_iter().any(|variable| {
        sh.var(variable)
            .is_ok_and(|value| value.eq_ignore_ascii_case("true"))
    })
}

fn run_tests(sh: &Shell, simulator_id: &str) -> Result<()> {
    println!("Running Swift tests on simulator {simulator_id}...");
    let destination = format!("platform=iOS Simulator,id={simulator_id}");
    let _tests_dir = sh.push_dir(TESTS_DIR);
    cmd!(
        sh,
        "xcodebuild test -scheme WalletKitForeignTestPackage -destination {destination} -sdk iphonesimulator CODE_SIGNING_ALLOWED=NO"
    )
    .run()
    .context("Swift foreign-binding tests failed")
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEVICES: &str = "== Devices ==\n-- iOS 26.0 --\n    iPhone 16 Pro (AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE) (Shutdown)\n    iPhone SE (11111111-2222-3333-4444-555555555555) (Booted)\n";

    #[test]
    fn prefers_named_simulator() {
        assert_eq!(
            simulator_id(DEVICES, "iPhone 16").as_deref(),
            Some("AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE")
        );
    }

    #[test]
    fn finds_any_iphone_as_fallback() {
        assert_eq!(
            simulator_id(DEVICES, "iPhone").as_deref(),
            Some("AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE")
        );
    }

    #[test]
    fn skips_parenthesized_text_in_device_name() {
        let devices = "    iPhone SE (3rd generation) (11111111-2222-3333-4444-555555555555) (Shutdown)";

        assert_eq!(
            simulator_id(devices, "iPhone").as_deref(),
            Some("11111111-2222-3333-4444-555555555555")
        );
    }
}
