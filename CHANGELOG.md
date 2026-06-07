# Changelog

All notable changes to this project are documented in this file.

The format follows the spirit of [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project uses semantic versioning.

## [0.2.0] - 2026-06-08

### Added

- Added upgradeability and initialization detector family:
  - `SOLSEC-INIT-001` - Reinitializable Initializer
  - `SOLSEC-INIT-002` - Constructor in Upgradeable Contract
  - `SOLSEC-INIT-004` - Uninitialized OwnableUpgradeable
- Added experimental upgradeability rules:
  - `SOLSEC-INIT-003` - Missing Storage Gap in Upgradeable Contract
  - `SOLSEC-INIT-005` - Override Removes Restriction
- Added `--experimental` scan flag for opt-in detectors with higher project-context sensitivity.
- Added fixture coverage for initializer, constructor, storage-gap, OwnableUpgradeable, and override restriction cases.
- Added README banner and improved project presentation.

### Changed

- Moved storage-gap and override-removes-restriction detectors behind explicit experimental opt-in.
- Softened storage-gap messaging to informational "consider" language.
- Lowered storage-gap findings to `LOW` severity and `LOW` confidence.
- Improved reinitializable initializer guard detection for multi-line function signatures.
- Improved override restriction detection for multi-line signatures and same-file inheritance chains.
- Removed cross-file heuristic findings from override-removes-restriction until project-level inheritance context is available.

### Fixed

- Fixed false positives for proxy one-time initializer guards such as `_implementation() == address(0)`.
- Fixed noisy mock/test path scanning by skipping common test and mock directories by default.
- Fixed several detector compile/test integration issues around rule metadata, fixture loading, and default detector registration.

### Notes

- `SOLSEC-INIT-003` and `SOLSEC-INIT-005` are experimental and disabled in default scans.
- Enable experimental detectors with:

  ```bash
  solsec scan ./contracts --experimental
  ```

## [0.1.0] - 2026-06-02

### Added

- Initial beta release of Solsec.
- Core Solidity detector set for reentrancy, `tx.origin`, delegatecall, unchecked calls, access control, and integer arithmetic risks.
- Text, JSON, SARIF, and Markdown reporting.
- Baseline, suppression, config, cache, git-diff, on-chain, inter-contract, and formal-verification bridge foundations.
