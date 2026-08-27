//! Android library and Kotlin binding generation.

use std::path::Path;

use eyre::{bail, Result, WrapErr as _};
use xshell::{cmd, Shell};

const DEFAULT_CARGO_FEATURES: &str = "compress-zkeys,embed-zkeys,v3";
const TARGET_DIR: &str = "target";

/// Build profile for the native libraries backing the Android AAR. Both profiles
/// build the same Android targets; only optimization level, symbols, and output
/// directory differ. Unlike Swift's `Profile`, no RUSTFLAGS distinguish the two —
/// Android has no `-application_extension`/dead-strip/bitcode equivalent, and the
/// root `Cargo.toml`'s explicit `[profile.release] debug = false` already gives
/// cargo's default `dev` profile full debug symbols for free.
#[derive(Clone, Copy)]
pub(super) enum Profile {
    /// Optimized. Used for distributed releases.
    Release,
    /// Unoptimized with full debug symbols, for native (LLDB-via-NDK)
    /// source-level debugging.
    Debug,
}

impl Profile {
    pub(super) const fn from_debug_flag(debug: bool) -> Self {
        if debug {
            Self::Debug
        } else {
            Self::Release
        }
    }

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
}

struct AndroidTarget {
    rust_name: &'static str,
}

const ANDROID_TARGETS: [AndroidTarget; 4] = [
    AndroidTarget {
        rust_name: "aarch64-linux-android",
    },
    AndroidTarget {
        rust_name: "armv7-linux-androideabi",
    },
    AndroidTarget {
        rust_name: "x86_64-linux-android",
    },
    AndroidTarget {
        rust_name: "i686-linux-android",
    },
];

pub(super) fn run(
    sh: &Shell,
    artifacts_dir: Option<&Path>,
    profile: Profile,
) -> Result<()> {
    if artifacts_dir.is_none() {
        ensure_android_toolchain(sh)?;
    } else {
        stage_native_libraries(sh, artifacts_dir.expect("checked above"), profile)?;
    }

    pack_bindings(sh, profile, artifacts_dir.is_some())?;

    println!("Kotlin/Android build complete.");
    Ok(())
}

fn ensure_android_toolchain(sh: &Shell) -> Result<()> {
    let missing_linkers = ANDROID_TARGETS
        .iter()
        .map(|target| {
            format!(
                "CARGO_TARGET_{}_LINKER",
                target.rust_name.replace('-', "_").to_ascii_uppercase()
            )
        })
        .filter(|variable| sh.var_os(variable).is_none_or(|linker| linker.is_empty()))
        .collect::<Vec<_>>();

    if !missing_linkers.is_empty() {
        bail!(
            "Android cross-compilation environment is not configured; missing:\n  {}\n\
             Run inside the Nix devshell:\n  \
             nix develop .#android --command cargo xtask kotlin build\n\
             Or use Docker without Nix:\n  \
             nix/docker.sh develop .#android --command cargo xtask kotlin build",
            missing_linkers.join("\n  ")
        );
    }

    Ok(())
}

fn pack_bindings(sh: &Shell, profile: Profile, no_build: bool) -> Result<()> {
    let features = cargo_features(sh);
    let release_flag = profile.cargo_profile_flag();
    let no_build_flag = no_build.then_some("--no-build");
    println!("Building and packaging BoltFFI Android bindings...");
    cmd!(sh, "boltffi pack android --deny-skipped")
        .args(release_flag)
        .args(no_build_flag)
        .args(["--cargo-arg=--locked", "--cargo-arg=--no-default-features"])
        .arg(format!("--cargo-arg=--features={features}"))
        .run()
        .wrap_err("failed to package BoltFFI Android bindings")
}

fn cargo_features(sh: &Shell) -> String {
    sh.var("WALLETKIT_CARGO_FEATURES")
        .ok()
        .filter(|features| !features.is_empty())
        .unwrap_or_else(|| DEFAULT_CARGO_FEATURES.to_owned())
}

fn stage_native_libraries(
    sh: &Shell,
    artifacts_dir: &Path,
    profile: Profile,
) -> Result<()> {
    println!("Staging Android static libraries for BoltFFI packaging...");
    for target in &ANDROID_TARGETS {
        let source = artifacts_dir
            .join(format!("android-{}", target.rust_name))
            .join("libwalletkit_core.a");
        let destination_dir = Path::new(TARGET_DIR)
            .join(target.rust_name)
            .join(profile.dir_name());
        let destination = destination_dir.join("libwalletkit_core.a");

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn android_toolchain_requires_nonempty_linkers() -> Result<()> {
        let sh = Shell::new()?;

        for target in &ANDROID_TARGETS {
            let variable = format!(
                "CARGO_TARGET_{}_LINKER",
                target.rust_name.replace('-', "_").to_ascii_uppercase()
            );
            sh.set_var(variable, "/ndk/clang");
        }

        ensure_android_toolchain(&sh)?;

        sh.set_var("CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER", "");
        let error =
            ensure_android_toolchain(&sh).expect_err("empty linker should be rejected");
        assert!(error
            .to_string()
            .contains("CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER"));

        Ok(())
    }
}
