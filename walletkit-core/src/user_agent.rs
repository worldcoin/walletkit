//! User agent for HTTP requests.

/// Value sent in the `User-Agent` header for outbound HTTP calls (World App, client, and `walletkit-core` version).
#[derive(Debug, Clone, uniffi::Object)]
pub struct UserAgent {
    user_agent: String,
}

#[uniffi::export]
impl UserAgent {
    /// Create a new `UserAgent` instance for the specified World App version, client name, and OS version.
    #[uniffi::constructor]
    #[must_use]
    pub fn new(world_app_version: &str, client_name: &str, os_version: &str) -> Self {
        let walletkit_version = env!("CARGO_PKG_VERSION");
        let user_agent = format!("WorldApp/{world_app_version} walletkit-core/{walletkit_version} {client_name}/{os_version}");
        Self { user_agent }
    }

    /// Full `User-Agent` string for logging or custom HTTP stacks.
    #[must_use]
    pub fn as_string(&self) -> String {
        self.user_agent.clone()
    }
}

/// No World App or client details — just `walletkit-core/{version}`. For host integrations, use [`UserAgent::new`].
impl Default for UserAgent {
    fn default() -> Self {
        let walletkit_version = env!("CARGO_PKG_VERSION");
        let user_agent = format!("walletkit-core/{walletkit_version}");
        Self { user_agent }
    }
}

impl std::fmt::Display for UserAgent {
    /// Full `User-Agent` string, including `WorldApp/…` and client segments when set via [`Self::new`].
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.user_agent)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Crate version is baked in at **compile** time via `env!` — `set_var` in tests does not change it
    /// (set `CARGO_PKG_VERSION` at runtime only affects `std::env::var`, not `env!`).
    const CRATE_VERSION: &str = env!("CARGO_PKG_VERSION");

    #[test]
    fn test_new() {
        let user_agent = UserAgent::new("1.0.0", "iOS", "16.0");
        assert_eq!(
            user_agent.to_string(),
            format!("WorldApp/1.0.0 walletkit-core/{CRATE_VERSION} iOS/16.0"),
        );
    }

    #[test]
    fn test_default() {
        let user_agent = UserAgent::default();
        assert_eq!(
            user_agent.to_string(),
            format!("walletkit-core/{CRATE_VERSION}")
        );
    }
}
