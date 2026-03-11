# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.8.0](https://github.com/worldcoin/walletkit/compare/v0.6.5...v0.8.0) - 2026-03-11

### Added

- switch to tracing, revamp WalletKit.Logger ([#239](https://github.com/worldcoin/walletkit/pull/239))
- sanitized logger ([#277](https://github.com/worldcoin/walletkit/pull/277))
- add plaintext vault export/import for backup sync ([#279](https://github.com/worldcoin/walletkit/pull/279))
- expose Credential expires_at property ([#272](https://github.com/worldcoin/walletkit/pull/272))
- expose OPRF nodes error to FFI ([#260](https://github.com/worldcoin/walletkit/pull/260))
- SQLite refactor ([#197](https://github.com/worldcoin/walletkit/pull/197))

### Other

- [**breaking**] feature flag v3 proofs ([#234](https://github.com/worldcoin/walletkit/pull/234))
- enforce clippy warnings as errors across workspace ([#261](https://github.com/worldcoin/walletkit/pull/261))
- Add delete all credentials ([#231](https://github.com/worldcoin/walletkit/pull/231))
- publish walletkit-db ([#275](https://github.com/worldcoin/walletkit/pull/275))
- bump world-id-core to 0.5.x ([#270](https://github.com/worldcoin/walletkit/pull/270))
