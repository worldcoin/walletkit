# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.12.0](https://github.com/worldcoin/walletkit/compare/v0.11.3...v0.12.0) - 2026-04-02

### Added

- do not trigger backups on `delete_storage()` ([#343](https://github.com/worldcoin/walletkit/pull/343))
- add danger_sign_initiate_recovery_agent_update to Authenticator (PROTO-4477) ([#333](https://github.com/worldcoin/walletkit/pull/333))

### Other

- NFC non-retryable migration errors ([#345](https://github.com/worldcoin/walletkit/pull/345))

## [0.11.3](https://github.com/worldcoin/walletkit/compare/v0.11.2...v0.11.3) - 2026-04-01

### Added

- add account recovery mechanisms ([#330](https://github.com/worldcoin/walletkit/pull/330))

### Other

- bump world-id-protocol crates 0.7 → 0.8 and taceo-oprf 0.8 → 0.11 ([#337](https://github.com/worldcoin/walletkit/pull/337))

## [0.11.2](https://github.com/worldcoin/walletkit/compare/v0.11.1...v0.11.2) - 2026-03-26

### Added

- expose initiateRecoveryAgentUpdate and executeRecoveryAgentUpdate ([#320](https://github.com/worldcoin/walletkit/pull/320))
- walletkit cli  ([#294](https://github.com/worldcoin/walletkit/pull/294))
- add destroy credential storage method ([#322](https://github.com/worldcoin/walletkit/pull/322))

### Other

- Walletkit register recovery bindings ([#327](https://github.com/worldcoin/walletkit/pull/327))
- bump world-id-core 0.6 → 0.7 ([#325](https://github.com/worldcoin/walletkit/pull/325))

## [0.11.1](https://github.com/worldcoin/walletkit/compare/v0.11.0...v0.11.1) - 2026-03-24

### Added

- expose danger_sign_challenge ([#298](https://github.com/worldcoin/walletkit/pull/298))

### Fixed

- *(walletkit-db)* patch sqlite3mc_cipher_name to eliminate thread-safety race ([#301](https://github.com/worldcoin/walletkit/pull/301))

### Other

- `notify_vault_changed` when credential vault mutated ([#317](https://github.com/worldcoin/walletkit/pull/317))

## [0.11.0](https://github.com/worldcoin/walletkit/compare/v0.10.0...v0.11.0) - 2026-03-19

### Added

- [**breaking**] version bump to 0.6 with new RP signature ([#308](https://github.com/worldcoin/walletkit/pull/308))
- export credential store as raw bytes ([#307](https://github.com/worldcoin/walletkit/pull/307))
- expose TFH recovery agent address in defaults ([#299](https://github.com/worldcoin/walletkit/pull/299))
- production defaults ([#305](https://github.com/worldcoin/walletkit/pull/305))

### Fixed

- *(walletkit-core)* fix flaky test_session_cache_ttl TTL off-by-one ([#303](https://github.com/worldcoin/walletkit/pull/303))

## [0.10.0](https://github.com/worldcoin/walletkit/compare/v0.9.1...v0.10.0) - 2026-03-12

### Added

- notify host on vault mutations for backup sync ([#292](https://github.com/worldcoin/walletkit/pull/292))

### Other

- expose associated_data_hash ([#297](https://github.com/worldcoin/walletkit/pull/297))
- include expired credentials in list + add delete by ID ([#273](https://github.com/worldcoin/walletkit/pull/273))

## [0.9.1](https://github.com/worldcoin/walletkit/compare/v0.9.0...v0.9.1) - 2026-03-11

### Other

- pass explicit `dest_dir` for vault backup export ([#282](https://github.com/worldcoin/walletkit/pull/282)). this API breaking change is for a feature not yet in production.
- add `BigInt` dep to swift ([#290](https://github.com/worldcoin/walletkit/pull/290)).

## [0.9.0](https://github.com/worldcoin/walletkit/compare/v0.8.0...v0.9.0) - 2026-03-11

### Added

- use ruint-uniffi for numbers ([#283](https://github.com/worldcoin/walletkit/pull/283))
