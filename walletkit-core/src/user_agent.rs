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
/// Starts with only `walletkit-core/{crate version}`. The embedding application supplies any
/// product / OS segments via [`Self::with`], prepended before the walletkit segment.
#[derive(Debug, Clone, uniffi::Object)]
pub struct UserAgentBuilder {
    segments: Vec<String>,
}

#[uniffi::export]
impl UserAgentBuilder {
    /// Initializes a new `UserAgentBuilder` with the crate version.
    #[uniffi::constructor]
    #[must_use]
    pub fn new() -> Self {
        let crate_version = env!("CARGO_PKG_VERSION");
        Self {
            segments: vec![format!("walletkit-core/{crate_version}")],
        }
    }

    /// Adds an `{app_name}/{app_version}` segment before the walletkit segment.
    ///
    /// Both must be non-empty to apply; otherwise returns an unchanged clone.
    #[must_use]
    pub fn with_app(&self, app_name: &str, app_version: &str) -> Self {
        let mut next = self.clone();
        next.segments.insert(0, format!("{app_name}/{app_version}"));
        next
    }

    /// Adds a `{client_name}/{client_version}` segment after the walletkit segment.
    ///
    /// For example `with_client("iOS", "17.0")` will produce `iOS/17.0` in the User-Agent string.
    /// Returns an unchanged clone if either `client_name` or `client_version` is empty.
    #[must_use]
    pub fn with_client(&self, client_name: &str, client_version: &str) -> Self {
        let mut next = self.clone();
        next.segments
            .push(format!("{client_name}/{client_version}"));
        next
    }

    /// Finalizes the header value as [`UserAgent`].
    #[must_use]
    pub fn build(&self) -> UserAgent {
        UserAgent(self.segments.join(" "))
    }
}

// Default implementation for UserAgentBuilder
impl Default for UserAgentBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Crate version is baked in at **compile** time via `env!`.
    const CRATE_VERSION: &str = env!("CARGO_PKG_VERSION");

    #[test]
    fn user_agent_builder_table() {
        let cases: Vec<(UserAgentBuilder, String)> = vec![
            (
                UserAgentBuilder::new(),
                format!("walletkit-core/{CRATE_VERSION}"),
            ),
            (
                UserAgentBuilder::new().with_app("WorldApp".into(), "1.0".into()),
                format!("WorldApp/1.0 walletkit-core/{CRATE_VERSION}"),
            ),
            (
                UserAgentBuilder::new()
                    .with_app("WorldApp".into(), "2.1".into())
                    .with_client("iOS".into(), "17.0".into()),
                format!("WorldApp/2.1 walletkit-core/{CRATE_VERSION} iOS/17.0"),
            ),
            (
                UserAgentBuilder::new().with_client("CLI".into(), "1.2.3".into()),
                format!("walletkit-core/{CRATE_VERSION} CLI/1.2.3"),
            ),
        ];

        for (builder, expected) in cases {
            assert_eq!(builder.build().to_string(), expected);
        }
    }
}
