//! User agent for HTTP requests.

/// Represents a User-Agent string.
#[derive(Debug, Clone, uniffi::Object)]
pub struct UserAgent(pub String);

/// Converts the [`UserAgent`] to a [`String`].
impl std::fmt::Display for UserAgent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)?;
        Ok(())
    }
}

/// Builds the [`UserAgent`] string sent as the HTTP `User-Agent` header.
///
/// Starts empty; call [`Self::with_segment`] for arbitrary `name/version` tokens and
/// [`Self::with_walletkit_segment`] for the library token (in whatever order fits the host — e.g.
/// native app vs web authenticator may omit an app-like segment entirely).
#[derive(Debug, Clone, uniffi::Object)]
pub struct UserAgentBuilder {
    segments: Vec<String>,
}

#[uniffi::export]
impl UserAgentBuilder {
    /// Empty builder — add segments with [`Self::with_segment`] and/or [`Self::with_walletkit_segment`].
    #[uniffi::constructor]
    #[must_use]
    pub const fn new() -> Self {
        Self {
            segments: Vec::new(),
        }
    }

    /// Appends `{product}/{version}` (e.g. `WorldApp/2.1`, `Chrome/120`). No-op if either side is empty after trim.
    #[must_use]
    pub fn with_segment(&self, name: &str, version: &str) -> Self {
        let mut next = self.clone();
        next.segments.push(format!("{name}/{version}"));
        next
    }

    /// Appends `walletkit-core/{crate version}`.
    #[must_use]
    pub fn with_walletkit_segment(&self) -> Self {
        let mut next = self.clone();
        let crate_version = env!("CARGO_PKG_VERSION");
        next.segments
            .push(format!("walletkit-core/{crate_version}"));
        next
    }

    /// Finalizes the header value as [`UserAgent`].
    #[must_use]
    pub fn build(&self) -> UserAgent {
        UserAgent(self.segments.join(" "))
    }
}

impl Default for UserAgentBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;

    #[test_case(
        &UserAgentBuilder::new().with_walletkit_segment(),
        concat!("walletkit-core/", env!("CARGO_PKG_VERSION"));
        "walletkit_only"
    )]
    #[test_case(
        &UserAgentBuilder::new()
            .with_segment("WorldApp", "1.0")
            .with_walletkit_segment(),
        concat!("WorldApp/1.0 walletkit-core/", env!("CARGO_PKG_VERSION"));
        "world_app_then_walletkit"
    )]
    #[test_case(
        &UserAgentBuilder::new()
            .with_segment("WorldApp", "2.1")
            .with_walletkit_segment()
            .with_segment("iOS", "17.0"),
        concat!("WorldApp/2.1 walletkit-core/", env!("CARGO_PKG_VERSION"), " iOS/17.0");
        "native_style_world_walletkit_os"
    )]
    #[test_case(
        &UserAgentBuilder::new()
            .with_walletkit_segment()
            .with_segment("CLI", "1.2.3"),
        concat!("walletkit-core/", env!("CARGO_PKG_VERSION"), " CLI/1.2.3");
        "walletkit_then_cli"
    )]
    fn user_agent_builder_expected(builder: &UserAgentBuilder, expected: &'static str) {
        assert_eq!(builder.build().to_string(), expected);
    }
}
