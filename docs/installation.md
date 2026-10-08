# Install WalletKit

WalletKit is published for Rust, iOS, Android, and the browser. Choose the section
for your platform.

## Rust

WalletKit is published on crates.io as [`walletkit`](https://crates.io/crates/walletkit). To add it
to a Rust project with the proving keys embedded, run the following command:

```sh
cargo add walletkit --features embed-zkeys
```

The `walletkit` crate has these Cargo features:

| Feature          | Default | Effect                                                                                                                                                |
| ---------------- | ------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| `issuers`        | Yes     | Clients for credential issuers, such as `TfhNfcIssuer` and `RecoveryBindingManager`.                                                                  |
| `embed-zkeys`    | No      | Embeds the proving keys in the binary. `EmbeddedZkArtifacts` and `CachingZkArtifacts` need it, so enable it to generate proofs.                       |
| `compress-zkeys` | No      | Compresses the embedded keys, which roughly halves the bundle size but makes decompression expensive. `CachingZkArtifacts` caches the result on disk. |
| `v3`             | No      | The legacy World ID 3.0 API, in the `v3` module.                                                                                                      |
| `semaphore`      | No      | Semaphore proofs for the legacy API. `v3` enables it.                                                                                                 |

The Swift and Kotlin packages are built with `embed-zkeys`, `compress-zkeys`, and
`v3`.

## iOS

WalletKit's Swift package is published from a separate repository,
[`worldcoin/walletkit-swift`](https://github.com/worldcoin/walletkit-swift), which
holds the prebuilt binaries. It supports iOS 13 and later. To add it to an Xcode
project, do the following:

1. In Xcode, click **File > Add Package Dependencies**.
1. Enter `https://github.com/worldcoin/walletkit-swift`, choose a version, and
   click **Add Package**.
1. Add the `WalletKit` product to your app's target.

## Android

WalletKit's Kotlin bindings are published to GitHub Packages and support Android
API level 23 and later. To add them to an Android app, do the following:

1. Add the GitHub Packages repository to your Gradle repositories. GitHub Packages
   requires credentials with the `read:packages` scope, even for public packages.
   This example reads them from the `gpr.user` and `gpr.key` Gradle properties;
   set those in your user-level `~/.gradle/gradle.properties` or in CI, and never
   commit them:

   ```kotlin
   repositories {
       maven {
           url = uri("https://maven.pkg.github.com/worldcoin/walletkit")
           credentials {
               username = providers.gradleProperty("gpr.user").get()
               password = providers.gradleProperty("gpr.key").get()
           }
       }
   }
   ```

1. In the app module's `build.gradle.kts`, add the dependency, replacing `VERSION`
   with a WalletKit version:

   ```kotlin
   dependencies {
       implementation("org.world:walletkit:VERSION")
   }
   ```

1. Sync Gradle.

## Browser

WalletKit is published on npm as
[`@worldcoin/walletkit-web`](https://www.npmjs.com/package/@worldcoin/walletkit-web). To add it to a web app, run the following
command:

```sh
npm install @worldcoin/walletkit-web
```

For requirements and a walkthrough, see
[Use WalletKit in the browser](web/package.md).
