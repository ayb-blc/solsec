# Changelog

All notable changes to this project are documented in this file.

The format follows the spirit of [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project uses semantic versioning.

## [0.3.0] - 2026-06-10

### Added

- Added DeFi-focused detector coverage:
  - `SOLSEC-DEFI-001` - Flash Loan Provider Missing Guard
  - `SOLSEC-DEFI-002` - Flash Loan Callback Missing Caller Verification
  - `SOLSEC-DEFI-003` - Signature Replay
- Added project-level analysis engine foundations:
  - Inheritance graph construction across Solidity source files.
  - Function signature normalization and 4-byte selector resolution.
  - Modifier resolution for local, inherited, and well-known access-control modifiers.
  - Parent/child override tracking for inheritance-chain regressions.
  - State read/write tracking for ordered operation analysis.
  - Finding trace output for text, JSON, and SARIF reports.
- Added graph-aware reentrancy analysis using ordered state operations.
- Added SARIF `codeFlows` support for traced findings.
- Added JSON trace serialization for findings with evidence chains.
- Added regression fixtures and tests for flash loan, signature replay, inheritance graph, signatures, modifiers, override tracking, state tracking, and trace rendering.

### Changed

- Reentrancy findings can now explain the exact vulnerability path from state read to external call to unsafe state write.
- Reentrancy analysis now prefers graph/state-tracker context when available and falls back to legacy single-file heuristics only when project context is unavailable.
- JSON output now always emits stable arrays for `findings` and `by_file`, even when no findings exist.
- Improved detector precision against mature protocol/library codebases:
  - Internal/private setup functions are no longer reported as critical reentrancy findings without an external entrypoint.
  - OpenZeppelin proxy shell constructors are no longer reported as upgradeable-constructor issues.
  - Standard ERC-3156/OZ flash-mint implementations are no longer reported as missing reentrancy guards when repayment checks are present.
  - Solidity libraries and standalone `recover`/`tryRecover` helpers are no longer reported as signature replay issues.
  - Serialization length suffix casts such as `uint16(bytes(x).length)` are treated as low-risk encoding patterns instead of arithmetic vulnerabilities.

### Fixed

- Fixed graph-aware scan integration so detectors can receive project context during normal CLI scans.
- Fixed single-file scans to build local graph context before analysis.
- Fixed nil JSON slices that caused `jq '.findings[]'` to fail when scans produced zero findings.
- Fixed package documentation comments for the `inheritancegraph` and `trace` packages.
- Reduced OpenZeppelin default-scan noise from seven findings to zero in local validation.

### Example

New finding traces show the evidence chain behind a finding:

```text
[1] Reentrancy: state write after external call in 'withdraw'
    ...testdata/fixtures/reentrancy/vulnerable.sol:16  [reentrancy]

    | (bool ok,) = msg.sender.call{value: amount}("");

    Evidence chain:
      READ   balances[msg.sender]   require check
      CALL   msg.sender.call()      external call; reentrancy window opens here
      WRITE  balances[msg.sender]   write AFTER external call; CEI violation

    Tags: reentrancy, cei, state-tracker
    Confidence: HIGH
```

### Notes

- This release is the first step toward a project-context-aware analysis engine.
- Full CFG/path-sensitive analysis is intentionally deferred; v0.3.0 focuses on high-ROI graph, modifier, state-operation, and trace infrastructure.

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
