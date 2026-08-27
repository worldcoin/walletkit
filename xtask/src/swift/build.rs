//! iOS library, Swift binding, and `XCFramework` generation.

use std::path::{Path, PathBuf};

use eyre::{bail, Result, WrapErr as _};
use xshell::{cmd, Shell};

const DEFAULT_CARGO_FEATURES: &str = "compress-zkeys,embed-zkeys,v3";
const FRAMEWORK_NAME: &str = "WalletKit.xcframework";
const INTERMEDIATE_DIR: &str = "swift/ios_build";
const PACKAGE_NAME: &str = "walletkit";
const SUPPORT_SOURCES_DIR: &str = "swift/support";
const TARGET_DIR: &str = "target";

const IOS_TARGETS: [&str; 3] = [
    "aarch64-apple-ios-sim",
    "aarch64-apple-ios",
    "x86_64-apple-ios",
];

/// Build profile for the native libraries backing the `XCFramework`. Both profiles build
/// the same iOS targets; only optimization level, symbols, and output directory differ.
#[derive(Clone, Copy)]
pub(super) enum Profile {
    /// Optimized, dead-stripped, symbols removed. Used for distributed releases.
    Release,
    /// Unoptimized with full debug symbols, for LLDB source-level debugging.
    Debug,
}

impl Profile {
    const fn cargo_profile_flag(self) -> Option<&'static str> {
        match self {
            Self::Release => Some("--release"),
            Self::Debug => None,
        }
    }

    const fn dir_name(self) -> &'static str {
        match self {
            Self::Release => "release",
            Self::Debug => "debug",
        }
    }

    const fn rustflags(self) -> &'static str {
        match self {
            Self::Release => {
                "-C link-arg=-Wl,-application_extension \
                 -C link-arg=-Wl,-dead_strip \
                 -C link-arg=-Wl,-dead_strip_dylibs \
                 -C embed-bitcode=no"
            }
            Self::Debug => {
                "-C link-arg=-Wl,-application_extension \
                 -C embed-bitcode=no"
            }
        }
    }
}

struct FrameworkSlice<'a> {
    directory: &'a str,
    library: PathBuf,
    platform: &'a str,
}

pub(super) fn run(
    sh: &Shell,
    output_dir: Option<&Path>,
    profile: Profile,
) -> Result<()> {
    ensure_macos()?;
    ensure_ios_sdks(sh)?;
    ensure_nargo(sh)?;

    let output_dir = resolve_output_dir(output_dir);
    let sources_dir = output_dir.join("Sources/WalletKit");
    let framework_output = output_dir.join(FRAMEWORK_NAME);

    println!(
        "Building {FRAMEWORK_NAME} to {} ({})",
        framework_output.display(),
        profile.dir_name()
    );

    sh.remove_path(INTERMEDIATE_DIR)?;
    sh.remove_path(&framework_output)?;
    sh.create_dir(format!("{INTERMEDIATE_DIR}/bindings"))?;
    sh.create_dir(format!(
        "{INTERMEDIATE_DIR}/target/universal-ios-sim/release"
    ))?;
    sh.create_dir(&sources_dir)?;

    configure_ios_build(sh, profile);
    build_native_libraries(sh, profile)?;
    create_universal_simulator_library(sh, profile)?;
    generate_bindings(sh, &sources_dir, profile)?;
    create_xcframework(sh, &framework_output, profile)?;

    sh.remove_path(INTERMEDIATE_DIR)?;

    println!(
        "Swift framework built successfully at: {}",
        framework_output.display()
    );
    Ok(())
}

fn ensure_macos() -> Result<()> {
    if !cfg!(target_os = "macos") {
        bail!("Swift/iOS builds require macOS and Xcode");
    }
    Ok(())
}

fn ensure_ios_sdks(sh: &Shell) -> Result<()> {
    for sdk in ["iphoneos", "iphonesimulator"] {
        if cmd!(sh, "xcrun --sdk {sdk} --show-sdk-path")
            .quiet()
            .ignore_stdout()
            .ignore_stderr()
            .run()
            .is_err()
        {
            bail!(
                "Xcode SDK `{sdk}` is unavailable; select a full Xcode installation, for example:\n  \
                 sudo xcode-select --switch /Applications/Xcode.app/Contents/Developer"
            );
        }
    }
    Ok(())
}

fn ensure_nargo(sh: &Shell) -> Result<()> {
    if cmd!(sh, "nargo --version")
        .quiet()
        .ignore_stdout()
        .ignore_stderr()
        .run()
        .is_err()
    {
        bail!(
            "nargo v1.0.0-beta.11 is required; install it with noirup or use the Nix default devshell"
        );
    }
    Ok(())
}

fn resolve_output_dir(output_dir: Option<&Path>) -> PathBuf {
    output_dir.map_or_else(
        || PathBuf::from("swift"),
        |directory| {
            if directory.is_absolute() {
                directory.to_path_buf()
            } else {
                Path::new("swift").join(directory)
            }
        },
    )
}

fn configure_ios_build(sh: &Shell, profile: Profile) {
    sh.set_var("IPHONEOS_DEPLOYMENT_TARGET", "13.0");
    // aws-lc-sys references Linux-only entropy definitions while compiling an
    // unreachable iOS code path. Keep this workaround scoped to aws-lc-sys.
    sh.set_var(
        "AWS_LC_SYS_CFLAGS",
        "-DRNDGETENTCNT=2 -Wno-implicit-function-declaration",
    );
    sh.set_var("RUSTFLAGS", profile.rustflags());
}

fn build_native_libraries(sh: &Shell, profile: Profile) -> Result<()> {
    let features = cargo_features(sh);
    let release_flag = profile.cargo_profile_flag();
    println!("Building WalletKit for iOS targets...");

    for target in IOS_TARGETS {
        println!("Building {target}...");
        cmd!(
            sh,
            "cargo build --package {PACKAGE_NAME} --target {target} --locked --target-dir {TARGET_DIR} --features {features}"
        )
        .args(release_flag)
        .run()
        .wrap_err_with(|| format!("failed to build WalletKit for {target}"))?;
    }

    Ok(())
}

fn cargo_features(sh: &Shell) -> String {
    sh.var("WALLETKIT_CARGO_FEATURES")
        .ok()
        .filter(|features| !features.is_empty())
        .unwrap_or_else(|| DEFAULT_CARGO_FEATURES.to_owned())
}

fn create_universal_simulator_library(sh: &Shell, profile: Profile) -> Result<()> {
    let arm_library = Path::new(TARGET_DIR)
        .join("aarch64-apple-ios-sim")
        .join(profile.dir_name())
        .join("libwalletkit.a");

    let intel_library = Path::new(TARGET_DIR)
        .join("x86_64-apple-ios")
        .join(profile.dir_name())
        .join("libwalletkit.a");

    let output = Path::new(INTERMEDIATE_DIR)
        .join("target/universal-ios-sim/release/libwalletkit.a");

    println!("Combining simulator targets into a universal binary...");
    cmd!(
        sh,
        "lipo -create {arm_library} {intel_library} -output {output}"
    )
    .run()
    .wrap_err("failed to create universal iOS simulator library")?;
    cmd!(sh, "lipo -info {output}")
        .run()
        .wrap_err("failed to inspect universal iOS simulator library")
}

fn generate_bindings(sh: &Shell, sources_dir: &Path, _profile: Profile) -> Result<()> {
    let bindings_dir = Path::new(INTERMEDIATE_DIR).join("bindings");
    let features = cargo_features(sh);

    println!("Generating Swift bindings...");
    cmd!(
        sh,
        "boltffi generate swift --deny-skipped --output {bindings_dir} --cargo-arg=--no-default-features"
    )
    .arg(format!("--cargo-arg=--features={features}"))
    .run()
    .wrap_err("failed to generate Swift bindings")?;

    let generated_source = bindings_dir.join("WalletkitCoreBoltFFI.swift");
    let destination = sources_dir.join("walletkit.swift");
    sh.copy_file(&generated_source, &destination)
        .wrap_err_with(|| {
            format!(
                "failed to move {} to {}",
                generated_source.display(),
                destination.display()
            )
        })?;
    sh.remove_path(&generated_source)?;

    let generated_header = bindings_dir.join("boltffi.h");
    sh.copy_file(&generated_header, bindings_dir.join("walletkit_coreFFI.h"))?;
    sh.write_file(
        bindings_dir.join("walletkit_coreFFI.modulemap"),
        "module walletkit_coreFFI {\n  header \"walletkit_coreFFI.h\"\n  export *\n}\n",
    )?;

    if sh.path_exists(SUPPORT_SOURCES_DIR) {
        copy_directory_contents(sh, Path::new(SUPPORT_SOURCES_DIR), sources_dir)?;
    }

    Ok(())
}

fn copy_directory_contents(
    sh: &Shell,
    source: &Path,
    destination: &Path,
) -> Result<()> {
    for source_path in sh
        .read_dir(source)
        .wrap_err_with(|| format!("failed to read {}", source.display()))?
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
                .wrap_err_with(|| {
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

fn create_xcframework(
    sh: &Shell,
    framework_output: &Path,
    profile: Profile,
) -> Result<()> {
    let bindings_dir = Path::new(INTERMEDIATE_DIR).join("bindings");
    let slices = [
        FrameworkSlice {
            directory: "ios-arm64",
            library: Path::new(TARGET_DIR)
                .join("aarch64-apple-ios")
                .join(profile.dir_name())
                .join("libwalletkit.a"),
            platform: "iPhoneOS",
        },
        FrameworkSlice {
            directory: "ios-arm64_x86_64-simulator",
            library: Path::new(INTERMEDIATE_DIR)
                .join("target/universal-ios-sim/release/libwalletkit.a"),
            platform: "iPhoneSimulator",
        },
    ];

    println!("Creating XCFramework...");
    for slice in &slices {
        let framework_dir = Path::new(INTERMEDIATE_DIR)
            .join("Frameworks")
            .join(slice.directory)
            .join("walletkit_coreFFI.framework");
        make_framework(
            sh,
            &framework_dir,
            &slice.library,
            slice.platform,
            &bindings_dir.join("walletkit_coreFFI.h"),
            &bindings_dir.join("walletkit_coreFFI.modulemap"),
        )?;
    }

    let device_framework = Path::new(INTERMEDIATE_DIR)
        .join("Frameworks/ios-arm64/walletkit_coreFFI.framework");
    let simulator_framework = Path::new(INTERMEDIATE_DIR)
        .join("Frameworks/ios-arm64_x86_64-simulator/walletkit_coreFFI.framework");
    cmd!(
        sh,
        "xcodebuild -create-xcframework -framework {device_framework} -framework {simulator_framework} -output {framework_output}"
    )
    .run()
    .wrap_err("failed to create WalletKit XCFramework")
}

fn make_framework(
    sh: &Shell,
    framework_dir: &Path,
    static_library: &Path,
    platform: &str,
    header: &Path,
    modulemap: &Path,
) -> Result<()> {
    sh.remove_path(framework_dir)?;
    sh.create_dir(framework_dir.join("Headers"))?;
    sh.create_dir(framework_dir.join("Modules"))?;
    sh.copy_file(static_library, framework_dir.join("walletkit_coreFFI"))?;
    sh.copy_file(header, framework_dir.join("Headers/walletkit_coreFFI.h"))?;

    let modulemap_contents = sh
        .read_file(modulemap)
        .wrap_err_with(|| format!("failed to read {}", modulemap.display()))?;
    let framework_modulemap = modulemap_contents
        .lines()
        .map(|line| {
            line.strip_prefix("module ").map_or_else(
                || line.to_owned(),
                |rest| format!("framework module {rest}"),
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    sh.write_file(
        framework_dir.join("Modules/module.modulemap"),
        format!("{framework_modulemap}\n"),
    )?;

    sh.write_file(
        framework_dir.join("Info.plist"),
        framework_info_plist(platform),
    )?;

    Ok(())
}

fn framework_info_plist(platform: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleDevelopmentRegion</key>
	<string>en</string>
	<key>CFBundleExecutable</key>
	<string>walletkit_coreFFI</string>
	<key>CFBundleIdentifier</key>
	<string>org.worldcoin.walletkit-coreFFI</string>
	<key>CFBundleInfoDictionaryVersion</key>
	<string>6.0</string>
	<key>CFBundleName</key>
	<string>walletkit_coreFFI</string>
	<key>CFBundlePackageType</key>
	<string>FMWK</string>
	<key>CFBundleShortVersionString</key>
	<string>1.0</string>
	<key>CFBundleVersion</key>
	<string>1</string>
	<key>CFBundleSupportedPlatforms</key>
	<array>
		<string>{platform}</string>
	</array>
	<key>MinimumOSVersion</key>
	<string>13.0</string>
</dict>
</plist>
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_output_directories_are_resolved_under_swift() {
        assert_eq!(
            resolve_output_dir(Some(Path::new("release"))),
            Path::new("swift/release")
        );
        assert_eq!(resolve_output_dir(None), Path::new("swift"));
    }

    #[test]
    fn framework_plist_contains_platform() {
        let plist = framework_info_plist("iPhoneSimulator");
        assert!(plist.contains("<string>iPhoneSimulator</string>"));
        assert!(plist.contains("<string>13.0</string>"));
    }
}
