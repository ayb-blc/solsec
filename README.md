<p align="center">
  <img src="assets/logo.png" alt="Solsec - Solidity Security Analyzer" width="100%" />
</p>

<h1 align="center">Solsec</h1>

<p align="center">
  <strong>Fast, CI-friendly static analysis for Solidity smart contracts.</strong>
</p>

<p align="center">
  <a href="#installation">Installation</a>
  ·
  <a href="#quick-start">Quick Start</a>
  ·
  <a href="#detectors">Detectors</a>
  ·
  <a href="#configuration">Configuration</a>
  ·
  <a href="#ci-example">CI</a>
</p>

<p align="center">
  <img alt="Status" src="https://img.shields.io/badge/status-v0.1.0--beta-0f6fff?style=for-the-badge" />
  <img alt="Language" src="https://img.shields.io/badge/Go-static%20analysis-00ADD8?style=for-the-badge&logo=go&logoColor=white" />
  <img alt="Target" src="https://img.shields.io/badge/Solidity-security%20scanner-363636?style=for-the-badge&logo=solidity&logoColor=white" />
  <img alt="License" src="https://img.shields.io/badge/license-MIT-green?style=for-the-badge" />
</p>

---

Solsec is a Web3 security scanner focused on high-signal findings, explainable
detector logic, and practical integration into developer workflows. It detects
common smart contract vulnerability patterns, emits machine-readable reports,
supports baselines and suppressions, and includes experimental bridges for
on-chain and formal verification workflows.

> [!IMPORTANT]
> Solsec is under active development. Treat results as security signals for
> review, not as a replacement for a professional smart contract audit.

---

## Highlights

| Area | Capability |
| --- | --- |
| Analysis | Solidity static analysis from files or directories |
| Signal quality | Low false-positive detector tuning against fixture suites and OpenZeppelin |
| Reporting | Text, JSON, SARIF, and Markdown output |
| GitHub integration | GitHub Code Scanning compatible SARIF |
| Configuration | `.solsec.yml` project configuration |
| Suppressions | Inline and config-based suppressions |
| CI adoption | Baseline support for CI/CD |
| Performance | Incremental cache and git-diff scanning |
| Project analysis | Cross-contract analysis mode |
| On-chain workflows | On-chain source fetching via Etherscan-compatible APIs |
| Verification bridge | Formal verification bridge for Echidna and Manticore target generation |

---

## Detectors

Core detectors currently include:

| Detector | Main Risk |
| --- | --- |
| Reentrancy | External interaction before state update |
| Cross-function reentrancy | Internal call path performs external interaction before effects |
| `tx.origin` misuse | Authentication based on transaction origin |
| Delegatecall risk | Unsafe or user-controlled delegatecall targets |
| Unchecked external call | Ignored `.call`, `.send`, `.delegatecall`, or `.staticcall` result |
| Access control | Missing or weak authorization on sensitive functions |
| Integer overflow / unchecked arithmetic | Pre-0.8 arithmetic risk, unchecked blocks, unsafe downcasts |

Advanced and experimental rule families include:

- Inter-contract call graph and taint flow
- Proxy and upgradeability risks
- On-chain bytecode/source mismatch checks
- Suspicious deployed bytecode patterns
- Formal-verification target generation from static findings

List all rules:

```bash
./bin/solsec rules list
```

Explain a detector or rule:

```bash
./bin/solsec explain reentrancy
```

---

## Installation

### Build From Source

```bash
git clone https://github.com/ayb-blc/solsec.git
cd solsec
go build -o bin/solsec ./cmd/solsec
```

### Verify

```bash
./bin/solsec --help
./bin/solsec scan --help
./bin/solsec rules list
```

---

## Quick Start

Scan one contract:

```bash
./bin/solsec scan contracts/Vault.sol
```

Scan a project directory:

```bash
./bin/solsec scan ./contracts
```

Emit JSON:

```bash
./bin/solsec scan ./contracts --format json --pretty
```

Emit SARIF for GitHub Code Scanning:

```bash
./bin/solsec scan ./contracts \
  --format sarif \
  --output results.sarif \
  --repo-root .
```

Fail CI on high or critical findings:

```bash
./bin/solsec scan ./contracts --fail-on high
```

Run selected detectors:

```bash
./bin/solsec scan ./contracts \
  --detectors reentrancy,unchecked-call,integer-overflow
```

---

## Configuration

Solsec can load a project-level `.solsec.yml`:

```yaml
version: "1"

scan:
  severity: low
  fail_on: high
  workers: 4
  timeout: 60

detectors:
  enable:
    - reentrancy
    - tx-origin
    - access-control
    - unchecked-call
    - delegatecall
    - integer-overflow
  disable: []

rules:
  override:
    SOLSEC-ARITHMETIC-003:
      severity: low
      confidence: low

exclude:
  - node_modules/**
  - lib/**
  - out/**
  - artifacts/**
  - cache/**
  - "**/*.t.sol"
  - test/**
  - script/**

ignore:
  - rule: SOLSEC-REENTRANCY-001
    file: contracts/legacy/OldVault.sol
    reason: "Legacy contract, migration planned"
    expiry: "2026-12-31"

  - rule: SOLSEC-ACCESS-001
    file: "test/**"
    reason: "Test contracts intentionally skip access control"

output:
  format: text
  no_color: false
```

Use an explicit config path:

```bash
./bin/solsec scan ./contracts --config .solsec.yml
```

CLI flags override config values where both are provided.

---

## Suppressions

Suppressions are useful for known, reviewed findings. Prefer documenting why a
finding is accepted and adding an expiry date for temporary exceptions.

Example `.solsec.yml` suppression:

```yaml
ignore:
  - rule: SOLSEC-AUTH-001
    file: contracts/GasStation.sol
    function: executeMetaTransaction
    reason: "Reviewed EIP-2771 meta-transaction pattern"
    expiry: "2026-12-31"
```

Use suppressions carefully. They should explain risk acceptance, not hide noisy
detectors.

---

## Baselines

Baselines let teams adopt Solsec without failing CI on existing known findings.
Only new findings break the build.

Create a baseline:

```bash
./bin/solsec baseline create ./contracts
```

Scan with a baseline:

```bash
./bin/solsec scan ./contracts --baseline solsec-baseline.json
```

Inspect the baseline:

```bash
./bin/solsec baseline show
```

Update it after reviewed findings are accepted:

```bash
./bin/solsec baseline update ./contracts
```

---

## Incremental Analysis

Solsec can cache file hashes and reuse results for unchanged files.

Cache-based incremental scan:

```bash
./bin/solsec scan ./contracts --incremental
```

Analyze only git changes:

```bash
./bin/solsec scan ./contracts \
  --git-diff \
  --git-ref origin/main
```

Show cache stats:

```bash
./bin/solsec scan ./contracts --cache-stats
```

Clear cache:

```bash
./bin/solsec scan ./contracts --clear-cache
```

---

## Inter-Contract Analysis

Enable project-wide cross-contract analysis:

```bash
./bin/solsec scan ./contracts --inter-contract
```

Specify a project root:

```bash
./bin/solsec scan ./contracts \
  --inter-contract \
  --inter-contract-root .
```

This mode is intended for protocol-level analysis where risk may span multiple
contracts through call graphs, shared state assumptions, or cross-contract taint
flow.

---

## On-Chain Analysis

Solsec can fetch verified source code from Etherscan-compatible APIs and scan it
through the normal analyzer pipeline.

```bash
ETHERSCAN_API_KEY=your_api_key ./bin/solsec scan ./contracts \
  --onchain \
  --network ethereum \
  --address 0x0000000000000000000000000000000000000000
```

Compare deployed bytecode against a local source path:

```bash
./bin/solsec scan ./contracts \
  --onchain \
  --network ethereum \
  --address 0x0000000000000000000000000000000000000000 \
  --onchain-source ./contracts/MyContract.sol
```

Supported network names include:

- `ethereum`
- `polygon`
- `arbitrum`
- `optimism`
- `bsc`
- `base`

---

## Formal Verification Bridge

Solsec can turn selected static findings into formal/fuzzing targets for tools
such as Echidna and Manticore.

Generate artifacts without running external tools:

```bash
./bin/solsec scan ./contracts \
  --formal \
  --formal-dry-run \
  --formal-output formal-verification
```

Run selected tools:

```bash
./bin/solsec scan ./contracts \
  --formal \
  --formal-tools echidna,manticore \
  --formal-timeout 300 \
  --formal-max-targets 5
```

External tools must be installed separately.

---

## CI Example

GitHub Actions example:

```yaml
name: Solsec

on:
  pull_request:
    paths:
      - "**/*.sol"

jobs:
  scan:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: actions/setup-go@v5
        with:
          go-version-file: go.mod

      - name: Build solsec
        run: go build -o bin/solsec ./cmd/solsec

      - name: Run scan
        run: |
          ./bin/solsec scan ./contracts \
            --git-diff \
            --git-ref origin/${{ github.base_ref }} \
            --format sarif \
            --output results.sarif \
            --fail-on high

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

---

## Testing

Run the default test suite:

```bash
make test
```

Run all Go tests:

```bash
go test ./...
```

Run detector-focused tests:

```bash
make test-detector DETECTOR=Reentrancy
```

Run accuracy tests:

```bash
make test-accuracy
```

Run benchmarks:

```bash
make test-bench
```

---

## Benchmarking Notes

Solsec is tested against:

- Vulnerable detector fixtures
- Safe detector fixtures
- Golden reporter outputs
- Mocked Etherscan responses
- OpenZeppelin Contracts smoke scans

Recent OpenZeppelin smoke result during detector tuning:

```text
Files analyzed: 350
Remaining findings: 1 review-worthy integer downcast
Critical findings: 0
High findings: 0
```

This benchmark is useful for false-positive tuning, but it is not a guarantee of
complete correctness. Detector behavior should be validated continuously as new
rules are added.

---

## Design Philosophy

Solsec favors high-signal findings over raw finding volume.

The analyzer uses a pragmatic mix of:

- lexical heuristics for fast pattern detection
- Solidity-aware function and block parsing
- version-aware arithmetic reasoning
- rule metadata for severity and remediation
- project-level features such as baselines, suppressions, and config overrides

Regex-only analysis can miss context. Full AST-only analysis can be heavier and
still requires semantic modeling. Solsec aims for a practical middle ground:
fast enough for CI, precise enough to be useful, and explainable enough for
security review.

---

## Limitations

- Static analysis can produce false positives and false negatives.
- Some detectors rely on heuristics rather than complete semantic execution.
- Complex DeFi invariants usually require manual review and protocol-specific
  reasoning.
- Formal verification output depends on external tools and generated targets.
- On-chain analysis depends on explorer availability and verified source data.

Always combine Solsec with manual review, tests, fuzzing, and professional audit
processes before production deployment.

---

## Planned

Planned improvements:

- Stronger AST and source-map integration
- Control-flow graph and data-flow precision
- Variable shadowing detector integration in the default scan pipeline
- More DeFi-specific detectors
- Better trace output for findings
- Expanded on-chain bytecode checks
- Better inter-contract taint modeling
- Versioned benchmark reports

---

## Contributing

Contributions, bug reports, feature requests, and detector ideas are welcome.

Suggested workflow:

1. Fork the repository
2. Create a feature branch
3. Add or update fixtures for detector changes
4. Run `go test ./...`
5. Submit a pull request

For detector work, include both vulnerable and safe fixtures where possible.

---

## License

MIT License
