# Changelog

All notable changes to this project are documented in this file.

The format follows the spirit of [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project uses semantic versioning.

## [0.4.0] - 2026-06-18

### Highlights

- Added a new DeFi risk detector set for vault, oracle, and token-approval patterns.
- Added lightweight path tracking for guard-aware detector precision without full CFG complexity.
- Added performance benchmarking with baseline save/compare support.
- Reduced false positives on mature production protocol codebases during local validation.

### Added

#### DeFi Detectors

| Rule ID | Detector | Severity Range |
| --- | --- | --- |
| `SOLSEC-DEFI-004` | ERC4626 Inflation Attack | CRITICAL/HIGH |
| `SOLSEC-DEFI-005` | Oracle Manipulation | CRITICAL/HIGH |
| `SOLSEC-DEFI-006` | Dangerous Approve / Allowance Pattern | CRITICAL/HIGH/MEDIUM/LOW |

- Added `SOLSEC-DEFI-004` for ERC4626 vault inflation risk, including first-depositor manipulation, donation-based share inflation, asset/share ratio abuse, and missing virtual-share or dead-share protections.
- Added `SOLSEC-DEFI-005` for oracle manipulation risk, including AMM spot-price dependencies, deprecated Chainlink APIs, missing staleness validation, and missing answer validity checks.
- Added `SOLSEC-DEFI-006` for dangerous token approvals, including user-controlled spenders, unguarded unlimited approvals, deprecated `safeApprove()` usage, and allowance race-condition patterns.

#### Lightweight Path Tracker

- Added `internal/pathtracker` for lightweight guard and branch context.
- Added early-guard detection for patterns such as `require(...)`, `if (...) return`, and initialization guards.
- Added custom mutex recognition for non-standard reentrancy guards.
- Integrated path-tracker context into reentrancy, access-control, and initialization analysis.

#### Benchmarking

- Added `solsec bench <target>` for local performance profiling.
- Added detector timing breakdowns, throughput metrics, memory statistics, and slowest-file reporting.
- Added benchmark baseline save/compare workflow:

  ```bash
  solsec bench ./contracts --save baseline.json
  solsec bench ./contracts --compare baseline.json --threshold 15
  ```

- Added noise-resistant regression detection so small millisecond-level detector fluctuations do not fail CI.
- Improved benchmark output readability with detector share percentages and compact profile bars.

### Changed

- Oracle analysis now distinguishes L2 sequencer uptime feeds from price feeds.
- Oracle analysis no longer reports price-staleness or price-validity findings for status-only sequencer feeds.
- Integer-overflow analysis now recognizes more bounded and intentional arithmetic patterns in optimized math libraries.
- Reinitializable-initializer analysis now skips Solidity interfaces and library helper functions.
- Constructor-in-upgradeable analysis now requires real upgradeability context instead of treating every `initialize()` function as an upgradeable-contract signal.
- Unchecked-call analysis now recognizes multi-line tuple assignment patterns followed by `require(success && ...)`.
- Benchmark collection now uses the same default path exclusions as normal scans, including test, mock, build artifact, cache, and dependency directories.
- Benchmark mean profiles now average detector timings across measured runs instead of displaying the last run as representative.

### Fixed

- Fixed false positives on Uniswap V3 interface `initialize()` declarations.
- Fixed false positives on Uniswap V3 library `initialize()` helper functions.
- Fixed false positives on non-upgradeable constructors that happened to coexist with an `initialize()` function.
- Fixed false positives on Uniswap-style safe low-level calls that validate both `success` and return data.
- Fixed excessive arithmetic noise in known optimized math-library patterns such as `BitMath` and `FullMath`.
- Fixed benchmark baseline comparison reporting for low-duration detector timings.

### Validation

Local protocol-validation snapshots used during v0.4.0 tuning:

| Target | Files | Default Findings | Notes |
| --- | ---: | ---: | --- |
| OpenZeppelin Contracts | 241 | 0 | Mature library validation target. |
| Aave V3 Core | 102 | 2 | Expected remaining findings: one oracle warning and one low-risk event downcast. |
| Uniswap V3 Core | 33 | 3 | `0` CRITICAL, `0` HIGH; remaining findings are MEDIUM arithmetic warnings. |

These counts are local validation snapshots and may change with upstream protocol revisions, remappings, or enabled detector sets.

### Performance

- Added repeatable benchmark runs with warmup support.
- Added per-detector timing and slowest-file visibility for performance tuning.
- Added baseline comparison suitable for CI regression checks.

Example workflow:

```bash
solsec bench /path/to/contracts --runs 5 --save baseline.json
solsec bench /path/to/contracts --runs 5 --compare baseline.json --threshold 15
```

### Notes

- v0.4.0 focuses on DeFi protocol security and detector precision.
- Full CFG/path-sensitive analysis remains intentionally deferred.
- Lightweight path tracking provides practical guard awareness with lower implementation complexity.
- This release continues building toward richer cross-contract analysis and taint propagation.

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
