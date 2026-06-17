// internal/detectors/erc4626_inflation.go

package detectors

import (
	"regexp"
	"strings"

	"github.com/ayb-blc/solsec/internal/analyzer"
	"github.com/ayb-blc/solsec/internal/rules"
)

// ERC4626InflationDetector finds ERC4626 vault contracts that are
// vulnerable to the share price inflation (first-depositor) attack.
//
// A vault is considered vulnerable when:
//  1. It inherits from ERC4626 or implements the ERC4626 interface
//  2. It has no recognised inflation protection mechanism
//
// Recognised protections (any one is sufficient):
//
//	A. _decimalsOffset() override returning > 0  (virtual shares, OZ v4.9+)
//	B. _convertToShares with `totalAssets() + 1` denominator
//	C. Dead shares: _mint(address(0)/dead, ...) before first deposit
//	D. MINIMUM_SHARES or MIN_INITIAL_SHARES constant / guard
type ERC4626InflationDetector struct {
	// Signals that identify an ERC4626 vault contract
	vaultInheritanceRe *regexp.Regexp   // "is ERC4626" or "is IERC4626"
	vaultFunctionsRe   []*regexp.Regexp // has deposit+convertToShares+totalAssets

	// Protection patterns — presence of any → safe
	protections []protectionCheck
}

type protectionCheck struct {
	name    string
	pattern *regexp.Regexp
}

func NewERC4626InflationDetector() *ERC4626InflationDetector {
	return &ERC4626InflationDetector{

		// Inheritance-based vault detection
		vaultInheritanceRe: regexp.MustCompile(
			`\bis\s+(?:\w+,\s*)*(?:ERC4626|IERC4626|ERC4626Upgradeable)\b`,
		),

		// Function-based vault detection (for interface implementors)
		vaultFunctionsRe: []*regexp.Regexp{
			regexp.MustCompile(`\bconvertToShares\s*\(`),
			regexp.MustCompile(`\btotalAssets\s*\(`),
			regexp.MustCompile(`\bfunction\s+deposit\s*\(`),
		},

		protections: []protectionCheck{
			{
				// A. Virtual shares: _decimalsOffset() override
				// OZ v4.9+ recommended pattern
				name: "_decimalsOffset override",
				pattern: regexp.MustCompile(
					`function\s+_decimalsOffset\s*\(\s*\)` +
						`\s*(?:internal|public|external|override|pure|virtual|\s)*` +
						`returns\s*\(\s*uint8\s*\)`,
				),
			},
			{
				// B. Manual +1 denominator in share conversion
				// shares = assets * supply / (totalAssets() + 1)
				name: "totalAssets()+1 denominator",
				pattern: regexp.MustCompile(
					`totalAssets\s*\(\s*\)\s*\+\s*1\b`,
				),
			},
			{
				// C1. Dead shares to address(0)
				name: "dead shares to address(0)",
				pattern: regexp.MustCompile(
					`_mint\s*\(\s*address\s*\(\s*0\s*\)`,
				),
			},
			{
				// C2. Dead shares to named dead address
				name: "dead shares to dead address",
				pattern: regexp.MustCompile(
					`_mint\s*\(\s*(?:DEAD_ADDRESS|dead|0xdead|address\(0xdead\))`,
				),
			},
			{
				// D. Minimum initial shares constant / guard
				name: "minimum shares protection",
				pattern: regexp.MustCompile(
					`(?i)(?:MINIMUM_SHARES|MIN_SHARES|MIN_INITIAL_SHARES|` +
						`MINIMUM_LIQUIDITY|minShares|minimumShares)`,
				),
			},
			{
				// E. mulDiv with virtual offset: supply + 10**offset
				// OZ v4.9 internal: assets.mulDiv(supply + 10**_decimalsOffset(), ...)
				name: "mulDiv with virtual offset",
				pattern: regexp.MustCompile(
					`totalSupply\s*\(\s*\)\s*\+\s*10\s*\*\*`,
				),
			},
			{
				// F. Explicit shares-per-asset scaling (alternative approaches)
				name: "SHARES_OFFSET or PRECISION scaling",
				pattern: regexp.MustCompile(
					`(?i)(?:SHARES_OFFSET|PRECISION_FACTOR|VIRTUAL_SHARES|INITIAL_SHARES)`,
				),
			},
		},
	}
}

func (d *ERC4626InflationDetector) Name() string                { return "erc4626-inflation" }
func (d *ERC4626InflationDetector) Severity() analyzer.Severity { return analyzer.Critical }
func (d *ERC4626InflationDetector) Description() string {
	return "Detects ERC4626 vaults missing inflation attack protection"
}

func (d *ERC4626InflationDetector) Analyze(
	lines []string,
	source string,
	filepath string,
) ([]analyzer.Finding, error) {

	contracts := extractERC4626ContractBlocks(lines)
	var findings []analyzer.Finding

	for _, c := range contracts {
		// Is this an ERC4626 vault?
		vaultKind, isVault := d.identifyVault(c, source)
		if !isVault {
			continue
		}

		// Abstract / interface definitions — only check concrete implementations
		if isAbstractOrInterface(c) {
			continue
		}

		// Check what protections are present in the contract source
		contractSrc := strings.Join(c.lines, "\n")
		found, protectionName := d.findProtection(contractSrc)
		if found {
			continue // Protected
		}

		// No protection found — determine severity
		severity := d.classifySeverity(c, vaultKind)

		finding := d.buildFinding(c, filepath, severity, protectionName, vaultKind)
		findings = append(findings, finding)
	}

	return findings, nil
}

func extractERC4626ContractBlocks(lines []string) []*contractBlock {
	contractStart := regexp.MustCompile(
		`^\s*(?:(interface)|(?:(abstract)\s+)?contract)\s+(\w+)(?:\s+is\s+([^{]+))?`,
	)

	var blocks []*contractBlock
	var current *contractBlock
	depth := 0

	for i, line := range lines {
		lineNum := i + 1

		if current == nil {
			m := contractStart.FindStringSubmatch(line)
			if m == nil {
				continue
			}

			name := m[3]
			current = &contractBlock{
				name:       name,
				header:     strings.TrimSpace(line),
				lines:      []string{line},
				startLine:  lineNum,
				isAbstract: m[1] == "interface" || m[2] == "abstract",
			}
			depth = 0
			for _, ch := range line {
				switch ch {
				case '{':
					depth++
				case '}':
					depth--
				}
			}
			if depth <= 0 && strings.Contains(line, "{") {
				blocks = append(blocks, current)
				current = nil
			}
			continue
		}

		current.lines = append(current.lines, line)
		for _, ch := range line {
			switch ch {
			case '{':
				depth++
			case '}':
				depth--
			}
		}
		if depth <= 0 {
			blocks = append(blocks, current)
			current = nil
		}
	}

	return blocks
}

// vaultKind distinguishes how we identified the vault.
type vaultKind uint8

const (
	vaultByInheritance vaultKind = iota // "is ERC4626"
	vaultByInterface                    // "is IERC4626" or implements functions
)

// identifyVault returns (kind, true) if the contract looks like an ERC4626 vault.
func (d *ERC4626InflationDetector) identifyVault(
	c *contractBlock,
	fullSource string,
) (vaultKind, bool) {

	// Check header for explicit ERC4626 inheritance
	if d.vaultInheritanceRe.MatchString(c.header) {
		return vaultByInheritance, true
	}

	// Check if contract implements the ERC4626 function set
	// (requires all three: convertToShares, totalAssets, deposit)
	contractSrc := strings.Join(c.lines, "\n")
	matchCount := 0
	for _, sig := range d.vaultFunctionsRe {
		if sig.MatchString(contractSrc) {
			matchCount++
		}
	}
	if matchCount == len(d.vaultFunctionsRe) {
		return vaultByInterface, true
	}

	return 0, false
}

// findProtection returns (true, protectionName) if any protection is present.
func (d *ERC4626InflationDetector) findProtection(src string) (bool, string) {
	for _, p := range d.protections {
		if p.pattern.MatchString(src) {
			return true, p.name
		}
	}
	return false, ""
}

// classifySeverity determines whether the issue is CRITICAL or HIGH.
//
// CRITICAL: clear ERC4626 inheritance, zero protection.
// HIGH: interface implementation or custom code — attack still possible
//
//	but may require more effort to exploit.
func (d *ERC4626InflationDetector) classifySeverity(
	c *contractBlock,
	kind vaultKind,
) analyzer.Severity {

	if kind == vaultByInheritance {
		return analyzer.Critical
	}
	return analyzer.High
}

func (d *ERC4626InflationDetector) buildFinding(
	c *contractBlock,
	filepath string,
	severity analyzer.Severity,
	_ string, // unused: no protection found so no name to show
	kind vaultKind,
) analyzer.Finding {

	how := "inherits ERC4626"
	if kind == vaultByInterface {
		how = "implements ERC4626 interface"
	}

	description := "Contract '" + c.name + "' " + how + " but has no share " +
		"inflation protection.\n\n" +
		"A malicious first depositor can:\n" +
		"  1. Deposit 1 wei → receive 1 share\n" +
		"  2. Directly transfer large amount to vault (donate)\n" +
		"  3. Next depositor's shares round down to 0 → funds stolen\n\n" +
		"Recommended fix: override _decimalsOffset() to return >= 3\n" +
		"(OpenZeppelin ERC4626 v4.9+ virtual shares)"

	finding := detectorFinding(
		rules.IDDefi004,
		filepath,
		c.startLine,
		"contract "+c.name+" is ERC4626 { ... }",
	)
	finding.Title = "ERC4626 vault '" + c.name + "' vulnerable to inflation attack"
	finding.Description = description
	finding.Confidence = analyzer.ConfidenceHigh
	finding.Severity = severity
	return finding
}

// isAbstractOrInterface returns true for non-deployable contracts.
func isAbstractOrInterface(c *contractBlock) bool {
	return c.isAbstract || strings.HasPrefix(strings.TrimSpace(c.header), "interface")
}
