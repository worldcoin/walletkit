//! Noir toolchain pinning.
//!
//! `Cargo.lock` is the authority: `world-id-proof`'s `build.rs` refuses to build
//! unless the installed `nargo` matches the Noir release encoded in the
//! `provekit_*` crate versions. Everything else that names a version — the
//! `noirup` steps, `nix/nargo.nix`, the docs — is a mirror, and mirrors drift.

use std::{ffi::OsStr, path::PathBuf};

use clap::Subcommand;
use eyre::{bail, Context as _, Result};
use xshell::{cmd, Shell};

/// `Cargo.lock` packages whose versions encode the Noir release as
/// `<noir-version>-alpha.<n>`.
const PROVEKIT_PREFIX: &str = "provekit_";

const WORKFLOWS_DIR: &str = ".github/workflows";
const NOIRUP_ACTION: &str = "noir-lang/noirup";
const NIX_DERIVATION: &str = "nix/nargo.nix";
const SWIFT_README: &str = "swift/README.md";

/// How far past a `noirup` step to look for its `toolchain:` input.
const TOOLCHAIN_LOOKAHEAD: usize = 6;

#[derive(Subcommand)]
pub enum Command {
    /// Print the `nargo` version required by `Cargo.lock`.
    Version,

    /// Fail if any pinned `nargo` version disagrees with `Cargo.lock`.
    CheckPins,
}

pub fn run(sh: &Shell, command: &Command) -> Result<()> {
    match command {
        Command::Version => {
            println!("{}", required_version(sh)?);
            Ok(())
        }
        Command::CheckPins => check_pins(sh),
    }
}

/// A pinned version that disagrees with `Cargo.lock`.
struct Drift {
    location: String,
    found: Option<String>,
}

/// Returns the `nargo` version `Cargo.lock` requires.
pub fn required_version(sh: &Shell) -> Result<String> {
    let lock = sh.read_file("Cargo.lock").context("reading Cargo.lock")?;
    required_version_from_lock(&lock)
}

/// Fails unless a `nargo` matching `Cargo.lock` is on `PATH`.
pub fn ensure_installed(sh: &Shell) -> Result<()> {
    let required = required_version(sh)?;

    let Ok(reported) = cmd!(sh, "nargo --version").quiet().ignore_stderr().read()
    else {
        bail!(
            "nargo {required} is required to build the Noir ownership-proof circuit, but nargo \
             was not found on PATH. Install it with `noirup --version v{required}`, or use the Nix \
             default devshell."
        );
    };

    if reported_version(&reported) != Some(required.as_str()) {
        bail!(
            "nargo {required} is required to produce circuit artifacts byte-identical to every \
             other builder's. `nargo --version` reported:\n{reported}"
        );
    }

    Ok(())
}

/// Reads the version off the `nargo version = X` line, ignoring the `noirc`
/// line. Exact rather than substring, so `1.0.0-beta.110` cannot satisfy a
/// requirement of `1.0.0-beta.11`.
fn reported_version(output: &str) -> Option<&str> {
    output.lines().find_map(|line| {
        Some(
            line.trim()
                .strip_prefix("nargo version")?
                .trim_start()
                .strip_prefix('=')?
                .trim(),
        )
    })
}

fn check_pins(sh: &Shell) -> Result<()> {
    let required = required_version(sh)?;
    let mut drifts = Vec::new();

    let nix = sh
        .read_file(NIX_DERIVATION)
        .with_context(|| format!("reading {NIX_DERIVATION}"))?;
    drifts.extend(check_nix_derivation(&nix, &required));

    let readme = sh
        .read_file(SWIFT_README)
        .with_context(|| format!("reading {SWIFT_README}"))?;
    drifts.extend(check_prose(&readme, SWIFT_README, &required));

    let mut noirup_steps = 0;
    for path in workflow_paths(sh)? {
        let display = path.display().to_string();
        let workflow = sh
            .read_file(&path)
            .with_context(|| format!("reading {display}"))?;
        noirup_steps += workflow.matches(NOIRUP_ACTION).count();
        drifts.extend(check_workflow(&workflow, &display, &required));
    }

    // Without this, moving noirup into a composite action or a `run:` line would
    // leave the parser finding nothing and the check passing on air.
    if noirup_steps == 0 {
        bail!(
            "no `{NOIRUP_ACTION}` step found in {WORKFLOWS_DIR}, so no CI pin was checked. If the \
             toolchain is now installed another way, teach this check how to find it."
        );
    }

    if drifts.is_empty() {
        println!("nargo pins agree with Cargo.lock: {required}");
        return Ok(());
    }

    let report = drifts
        .iter()
        .map(|drift| {
            format!(
                "  {} — {}",
                drift.location,
                describe(drift.found.as_deref())
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    bail!(
        "Cargo.lock requires nargo {required}, but these pins disagree:\n{report}\n\n\
         Update each to {required}. {NIX_DERIVATION} also carries a per-platform `hash` for the \
         release tarball — those must be refreshed for the new version, not just the version \
         string."
    );
}

fn describe(found: Option<&str>) -> String {
    found.map_or_else(|| "no version pinned".to_owned(), |v| format!("found {v}"))
}

/// Uses the shell's working directory, not the process's, so `cargo xtask` works
/// from any subdirectory.
fn workflow_paths(sh: &Shell) -> Result<Vec<PathBuf>> {
    let mut paths = sh
        .read_dir(WORKFLOWS_DIR)
        .with_context(|| format!("reading {WORKFLOWS_DIR}"))?
        .into_iter()
        .filter(|path| {
            path.extension().is_some_and(|ext| {
                ext == OsStr::new("yml") || ext == OsStr::new("yaml")
            })
        })
        .collect::<Vec<_>>();
    paths.sort();
    Ok(paths)
}

fn required_version_from_lock(lock: &str) -> Result<String> {
    let packages = provekit_packages(lock);

    if packages.is_empty() {
        bail!(
            "no `{PROVEKIT_PREFIX}*` package found in Cargo.lock, so the required nargo version \
             cannot be derived. If the Noir prover was removed, remove this check too."
        );
    }

    let mut bases: Vec<&str> = packages.iter().map(|(_, base)| *base).collect();
    bases.sort_unstable();
    bases.dedup();

    if let [base] = bases[..] {
        return Ok(base.to_owned());
    }

    let listing = packages
        .iter()
        .map(|(name, base)| format!("  {name} → {base}"))
        .collect::<Vec<_>>()
        .join("\n");
    bail!(
        "`{PROVEKIT_PREFIX}*` packages in Cargo.lock disagree on the Noir version, so the required \
         nargo version is ambiguous:\n{listing}"
    );
}

/// Returns each `provekit_*` package paired with its Noir base version.
fn provekit_packages(lock: &str) -> Vec<(&str, &str)> {
    let mut packages = Vec::new();
    let mut current: Option<&str> = None;

    for line in lock.lines().map(str::trim) {
        if let Some(name) = quoted_value(line, "name") {
            current = name.starts_with(PROVEKIT_PREFIX).then_some(name);
        } else if let Some(version) = quoted_value(line, "version") {
            if let Some(name) = current.take() {
                packages.push((name, base_version(version)));
            }
        }
    }

    packages
}

/// Strips the provekit fork's `-alpha.<n>` suffix, leaving the Noir version.
fn base_version(version: &str) -> &str {
    version
        .split_once("-alpha.")
        .map_or(version, |(base, _)| base)
}

fn quoted_value<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    line.strip_prefix(key)?
        .trim_start()
        .strip_prefix('=')?
        .trim_start()
        .strip_prefix('"')?
        .split('"')
        .next()
}

fn check_nix_derivation(content: &str, required: &str) -> Vec<Drift> {
    let found = content
        .lines()
        .map(str::trim)
        .find_map(|line| quoted_value(line, "version"));

    match found {
        Some(version) if version == required => Vec::new(),
        found => vec![Drift {
            location: format!("{NIX_DERIVATION} (version)"),
            found: found.map(str::to_owned),
        }],
    }
}

/// Flags any `v<version>` in prose that looks like a `nargo` pin but is stale.
fn check_prose(content: &str, path: &str, required: &str) -> Vec<Drift> {
    content
        .lines()
        .enumerate()
        .filter(|(_, line)| line.contains("nargo"))
        .filter_map(|(index, line)| {
            let found = tagged_version(line)?;
            (found != required).then(|| Drift {
                location: format!("{path}:{}", index + 1),
                found: Some(found.to_owned()),
            })
        })
        .collect()
}

fn check_workflow(content: &str, path: &str, required: &str) -> Vec<Drift> {
    let lines: Vec<&str> = content.lines().collect();

    lines
        .iter()
        .enumerate()
        .filter(|(_, line)| line.contains(NOIRUP_ACTION))
        .filter_map(|(index, _)| {
            let found = lines
                .iter()
                .skip(index + 1)
                .take(TOOLCHAIN_LOOKAHEAD)
                .find_map(|line| line.trim().strip_prefix("toolchain:"))
                .map(str::trim)
                .and_then(|value| value.strip_prefix('v'));

            match found {
                Some(version) if version == required => None,
                found => Some(Drift {
                    location: format!("{path}:{} (noirup)", index + 1),
                    found: found.map(str::to_owned),
                }),
            }
        })
        .collect()
}

/// Extracts a `v1.2.3`-style version, ignoring the `v`.
fn tagged_version(line: &str) -> Option<&str> {
    line.split_whitespace().find_map(|word| {
        let candidate =
            word.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '.');
        candidate
            .strip_prefix('v')
            .filter(|rest| rest.starts_with(|c: char| c.is_ascii_digit()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCK: &str = r#"
[[package]]
name = "provekit-common"
version = "0.1.4"

[[package]]
name = "provekit_nargo"
version = "1.0.0-beta.11-alpha.4"

[[package]]
name = "provekit_acir"
version = "1.0.0-beta.11-alpha.2"

[[package]]
name = "serde"
version = "1.0.230"
"#;

    #[test]
    fn derives_version_from_provekit_packages() {
        assert_eq!(required_version_from_lock(LOCK).unwrap(), "1.0.0-beta.11");
    }

    #[test]
    fn ignores_hyphenated_provekit_crates() {
        let packages = provekit_packages(LOCK);
        assert!(packages
            .iter()
            .all(|(name, _)| name.starts_with("provekit_")));
        assert_eq!(packages.len(), 2);
    }

    #[test]
    fn rejects_disagreeing_provekit_versions() {
        let skewed = LOCK.replace("1.0.0-beta.11-alpha.2", "1.0.0-beta.12-alpha.2");
        let error = required_version_from_lock(&skewed).unwrap_err().to_string();
        assert!(error.contains("disagree"), "{error}");
        assert!(error.contains("provekit_acir"), "{error}");
    }

    #[test]
    fn rejects_lock_without_provekit() {
        let error = required_version_from_lock(
            "[[package]]\nname = \"serde\"\nversion = \"1\"\n",
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("cannot be derived"), "{error}");
    }

    #[test]
    fn reads_version_off_the_nargo_line_not_the_noirc_line() {
        let output =
            "nargo version = 1.0.0-beta.11\nnoirc version = 1.0.0-beta.11+fd3925a\n";
        assert_eq!(reported_version(output), Some("1.0.0-beta.11"));
    }

    #[test]
    fn does_not_accept_a_longer_version_as_a_prefix_match() {
        let output = "nargo version = 1.0.0-beta.110\n";
        assert_ne!(reported_version(output), Some("1.0.0-beta.11"));
    }

    #[test]
    fn reports_no_version_for_unrecognised_output() {
        assert_eq!(reported_version("something else entirely\n"), None);
    }

    #[test]
    fn accepts_matching_nix_derivation() {
        let nix = "  pname = \"nargo\";\n  version = \"1.0.0-beta.11\";\n";
        assert!(check_nix_derivation(nix, "1.0.0-beta.11").is_empty());
    }

    #[test]
    fn flags_skewed_nix_derivation() {
        let nix = "  version = \"1.0.0-beta.10\";\n";
        let drifts = check_nix_derivation(nix, "1.0.0-beta.11");
        assert_eq!(drifts.len(), 1);
        assert_eq!(drifts[0].found.as_deref(), Some("1.0.0-beta.10"));
    }

    #[test]
    fn flags_nix_derivation_without_version() {
        let drifts = check_nix_derivation("  pname = \"nargo\";\n", "1.0.0-beta.11");
        assert_eq!(drifts.len(), 1);
        assert!(drifts[0].found.is_none());
    }

    #[test]
    fn accepts_matching_workflow_pin() {
        let workflow = "\
      - uses: noir-lang/noirup@7dbe69c # v0.1.4
        with:
          # a specific nargo toolchain version is required
          toolchain: v1.0.0-beta.11
";
        assert!(check_workflow(workflow, "ci.yml", "1.0.0-beta.11").is_empty());
    }

    #[test]
    fn flags_skewed_workflow_pin() {
        let workflow = "\
      - uses: noir-lang/noirup@7dbe69c # v0.1.4
        with:
          toolchain: v1.0.0-beta.10
";
        let drifts = check_workflow(workflow, "ci.yml", "1.0.0-beta.11");
        assert_eq!(drifts.len(), 1);
        assert_eq!(drifts[0].found.as_deref(), Some("1.0.0-beta.10"));
        assert!(
            drifts[0].location.contains("ci.yml:1"),
            "{}",
            drifts[0].location
        );
    }

    #[test]
    fn flags_workflow_pin_left_unset() {
        let workflow = "      - uses: noir-lang/noirup@7dbe69c # v0.1.4\n";
        let drifts = check_workflow(workflow, "ci.yml", "1.0.0-beta.11");
        assert_eq!(drifts.len(), 1);
        assert!(drifts[0].found.is_none());
    }

    #[test]
    fn flags_every_stale_workflow_pin_not_only_the_first() {
        let step = "\
      - uses: noir-lang/noirup@7dbe69c
        with:
          toolchain: v1.0.0-beta.10
";
        let drifts = check_workflow(&step.repeat(3), "ci.yml", "1.0.0-beta.11");
        assert_eq!(drifts.len(), 3);
    }

    #[test]
    fn does_not_confuse_the_noirup_action_tag_with_the_toolchain() {
        let workflow = "\
      - uses: noir-lang/noirup@7dbe69c # v0.1.4
        with:
          toolchain: v1.0.0-beta.11
";
        assert!(check_workflow(workflow, "ci.yml", "1.0.0-beta.11").is_empty());
    }

    #[test]
    fn flags_stale_prose_version() {
        let readme =
            "Xcode, the iOS Rust targets, and `nargo` v1.0.0-beta.10 installed.";
        let drifts = check_prose(readme, "swift/README.md", "1.0.0-beta.11");
        assert_eq!(drifts.len(), 1);
        assert_eq!(drifts[0].found.as_deref(), Some("1.0.0-beta.10"));
    }

    #[test]
    fn ignores_prose_without_nargo() {
        let readme = "Requires Xcode v16.0 and a recent toolchain.";
        assert!(check_prose(readme, "swift/README.md", "1.0.0-beta.11").is_empty());
    }
}
