//! Swift package manifest generation.

use eyre::{ensure, Result};

const BINARY_TARGET_PLACEHOLDER: &str = "        <binary_target>";

pub(super) fn local_manifest(template: &str, framework: &str) -> Result<String> {
    replace_binary_target(
        template,
        &format!(
            "        .binaryTarget(\n            name: \"walletkit_coreFFI\",\n            path: \"{framework}\"\n        )"
        ),
    )
}

pub(super) fn release_manifest(
    template: &str,
    asset_url: &str,
    checksum: &str,
    release_version: &str,
) -> Result<String> {
    let manifest = replace_binary_target(
        template,
        &format!(
            "        .binaryTarget(\n            name: \"walletkit_coreFFI\",\n            url: \"{asset_url}\",\n            checksum: \"{checksum}\"\n        )"
        ),
    )?;

    Ok(format!("{manifest}// Release version: {release_version}\n"))
}

fn replace_binary_target(template: &str, replacement: &str) -> Result<String> {
    ensure!(
        template.matches(BINARY_TARGET_PLACEHOLDER).count() == 1,
        "Swift package template must contain exactly one {BINARY_TARGET_PLACEHOLDER} placeholder"
    );

    Ok(template.replace(BINARY_TARGET_PLACEHOLDER, replacement))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEMPLATE: &str = "targets: [\n        <binary_target>\n]\n";

    #[test]
    fn renders_local_binary_target() -> Result<()> {
        let manifest = local_manifest(TEMPLATE, "WalletKit.xcframework")?;

        assert!(manifest.contains("path: \"WalletKit.xcframework\""));
        assert!(!manifest.contains(BINARY_TARGET_PLACEHOLDER));
        Ok(())
    }

    #[test]
    fn renders_release_binary_target_and_version() -> Result<()> {
        let manifest =
            release_manifest(TEMPLATE, "https://example.com/sdk.zip", "abc", "1.2.3")?;

        assert!(manifest.contains("url: \"https://example.com/sdk.zip\""));
        assert!(manifest.contains("checksum: \"abc\""));
        assert!(manifest.ends_with("// Release version: 1.2.3\n"));
        Ok(())
    }
}
