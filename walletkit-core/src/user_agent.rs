//! User agent for HTTP requests.

const WORLD_APP_USER_AGENT_PRODUCT: &str = "WorldApp";
const WORLD_ID_APP_USER_AGENT_PRODUCT: &str = "WorldID";
const WORLD_ID_ANDROID_CLIENT_NAME: &str = "android-id";
const WORLD_ID_IOS_CLIENT_NAME: &str = "ios-id";

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

#[uniffi::export]
impl UserAgent {
    /// Returns the header value for FFI consumers.
    #[must_use]
    pub fn header_value(&self) -> String {
        self.0.clone()
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

    /// Appends the app product segment for the client name.
    ///
    /// Uses `WorldID/{app_version}` for World ID app clients (`android-id` / `ios-id`),
    /// and `WorldApp/{app_version}` for all other clients.
    #[must_use]
    pub fn with_app_segment_for_client(
        &self,
        app_version: &str,
        client_name: &str,
    ) -> Self {
        self.with_segment(user_agent_product_for_client(client_name), app_version)
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

    /// Appends `{client_name}/{os_version}` to match the app client suffix convention.
    #[must_use]
    pub fn with_client_segment(&self, client_name: &str, os_version: &str) -> Self {
        self.with_segment(client_name, os_version)
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

fn user_agent_product_for_client(client_name: &str) -> &'static str {
    match client_name {
        WORLD_ID_ANDROID_CLIENT_NAME | WORLD_ID_IOS_CLIENT_NAME => {
            WORLD_ID_APP_USER_AGENT_PRODUCT
        }
        _ => WORLD_APP_USER_AGENT_PRODUCT,
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
    #[test_case(
        &UserAgentBuilder::new()
            .with_app_segment_for_client("4.0.2500", "android")
            .with_walletkit_segment()
            .with_client_segment("android", "15"),
        concat!("WorldApp/4.0.2500 walletkit-core/", env!("CARGO_PKG_VERSION"), " android/15");
        "world_app_android_client"
    )]
    #[test_case(
        &UserAgentBuilder::new()
            .with_app_segment_for_client("4.0.2500", "ios")
            .with_walletkit_segment()
            .with_client_segment("ios", "26.4.2"),
        concat!("WorldApp/4.0.2500 walletkit-core/", env!("CARGO_PKG_VERSION"), " ios/26.4.2");
        "world_app_ios_client"
    )]
    #[test_case(
        &UserAgentBuilder::new()
            .with_app_segment_for_client("1.0.100", "android-id")
            .with_walletkit_segment()
            .with_client_segment("android-id", "15"),
        concat!("WorldID/1.0.100 walletkit-core/", env!("CARGO_PKG_VERSION"), " android-id/15");
        "world_id_android_client"
    )]
    #[test_case(
        &UserAgentBuilder::new()
            .with_app_segment_for_client("1.0.100", "ios-id")
            .with_walletkit_segment()
            .with_client_segment("ios-id", "26.4.2"),
        concat!("WorldID/1.0.100 walletkit-core/", env!("CARGO_PKG_VERSION"), " ios-id/26.4.2");
        "world_id_ios_client"
    )]
    fn user_agent_builder_expected(builder: &UserAgentBuilder, expected: &'static str) {
        assert_eq!(builder.build().to_string(), expected);
    }

    #[test]
    fn user_agent_exposes_header_value_for_ffi_consumers() {
        let user_agent = UserAgentBuilder::new()
            .with_app_segment_for_client("1.0.100", "android-id")
            .with_walletkit_segment()
            .with_client_segment("android-id", "15")
            .build();

        assert_eq!(
            user_agent.header_value(),
            concat!(
                "WorldID/1.0.100 walletkit-core/",
                env!("CARGO_PKG_VERSION"),
                " android-id/15"
            )
        );
    }
}
