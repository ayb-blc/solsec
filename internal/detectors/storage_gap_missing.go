// internal/detectors/storage_gap_missing.go

package detectors

import (
	"regexp"
	"strings"

	"github.com/ayb-blc/solsec/internal/analyzer"
	"github.com/ayb-blc/solsec/internal/rules"
)

// StorageGapMissingDetector detects missing __gap storage reservations in upgradeable contracts.
//
// Severity model:
//
//	MEDIUM -> upgradeable base contract with state variables, inherited elsewhere, and no __gap
//
//	LOW    -> upgradeable leaf contract with state variables and no __gap
//
//	SKIP   -> has __gap, has no state variables, or is not upgradeable
type StorageGapMissingDetector struct {
	upgradeableSignals []*regexp.Regexp

	gapPatterns []*regexp.Regexp

	baseContractSignals []*regexp.Regexp

	stateVarPatterns []*regexp.Regexp

	excludePatterns []*regexp.Regexp

	contractStart *regexp.Regexp
}

func NewStorageGapMissingDetector() *StorageGapMissingDetector {
	return &StorageGapMissingDetector{

		upgradeableSignals: []*regexp.Regexp{
			regexp.MustCompile(`\bInitializable\b`),
			regexp.MustCompile(`\w+Upgradeable\b`),
			regexp.MustCompile(`\w+Upgradable\b`),
			regexp.MustCompile(`function\s+initialize\s*\(`),
			regexp.MustCompile(`__\w+_init\s*\(`),
		},

		gapPatterns: []*regexp.Regexp{
			regexp.MustCompile(`uint256\s*\[\s*\d+\s*\]\s*(?:private\s+|internal\s+)?__gap\b`),
			regexp.MustCompile(`\b__gap\b`),
		},

		// These signals indicate base-contract behavior and raise severity to MEDIUM.
		baseContractSignals: []*regexp.Regexp{
			// abstract contract keyword
			regexp.MustCompile(`^\s*abstract\s+contract\b`),
			regexp.MustCompile(`\bvirtual\b`),
			regexp.MustCompile(`contract\s+\w*(?:Base|Abstract|Storage|State|Core|Common|Logic|Impl)\w*\b`),
		},

		stateVarPatterns: []*regexp.Regexp{
			regexp.MustCompile(`^\s*mapping\s*\(`),
			regexp.MustCompile(`^\s*(?:uint\d*|int\d*|address|bool|bytes\d*|string)\s+(?:(?:public|private|internal)\s+)?\w+`),
			regexp.MustCompile(`^\s*[A-Z]\w+(?:\[\])?\s+(?:public|private|internal)\s+\w+`),
		},

		excludePatterns: []*regexp.Regexp{
			regexp.MustCompile(`\bconstant\b`),
			regexp.MustCompile(`\bimmutable\b`),
			regexp.MustCompile(`^\s*event\s+`),
			regexp.MustCompile(`^\s*error\s+`),
			regexp.MustCompile(`^\s*function\s+`),
			regexp.MustCompile(`^\s*modifier\s+`),
			regexp.MustCompile(`^\s*struct\s+`),
			regexp.MustCompile(`^\s*enum\s+`),
			regexp.MustCompile(`^\s*using\s+`),
			regexp.MustCompile(`^\s*//`),
			regexp.MustCompile(`^\s*\*`),
		},

		contractStart: regexp.MustCompile(
			`^\s*(?:abstract\s+)?contract\s+(\w+)`,
		),
	}
}

func (d *StorageGapMissingDetector) Name() string                { return "storage-gap-missing" }
func (d *StorageGapMissingDetector) Severity() analyzer.Severity { return analyzer.Low }
func (d *StorageGapMissingDetector) Description() string {
	return "Detects upgradeable base contracts missing __gap storage reservation"
}

func (d *StorageGapMissingDetector) Analyze(
	lines []string,
	source string,
	filepath string,
) ([]analyzer.Finding, error) {

	if !d.isUpgradeable(source) {
		return nil, nil
	}

	contracts := d.extractContractBlocks(lines)
	var findings []analyzer.Finding

	for _, c := range contracts {
		// Check contract-level upgradeability signals, not only file-level signals.
		contractSource := strings.Join(c.lines, "\n")
		if !d.isUpgradeable(contractSource) {
			continue
		}

		if d.hasGap(contractSource) {
			continue
		}

		stateVars := d.collectStateVars(c)
		if len(stateVars) == 0 {
			continue
		}

		baseLike := d.isBaseLike(source, c)
		finding := d.buildFinding(c, filepath, baseLike, stateVars)
		findings = append(findings, finding)
	}

	return findings, nil
}

// --- Contract block extraction ---

type contractBlock struct {
	name       string
	lines      []string
	startLine  int
	isAbstract bool
}

func (d *StorageGapMissingDetector) extractContractBlocks(
	lines []string,
) []*contractBlock {

	var blocks []*contractBlock
	var current *contractBlock
	depth := 0

	for i, line := range lines {
		lineNum := i + 1

		if current == nil {
			m := d.contractStart.FindStringSubmatch(line)
			if m != nil {
				current = &contractBlock{
					name:       m[1],
					startLine:  lineNum,
					isAbstract: strings.Contains(line, "abstract"),
					lines:      []string{line},
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

		if depth == 0 && len(current.lines) > 0 {
			blocks = append(blocks, current)
			current = nil
		}
	}

	return blocks
}

// --- Detection helpers ---

func (d *StorageGapMissingDetector) isUpgradeable(source string) bool {
	for _, signal := range d.upgradeableSignals {
		if signal.MatchString(source) {
			return true
		}
	}
	return false
}

func (d *StorageGapMissingDetector) hasGap(source string) bool {
	for _, p := range d.gapPatterns {
		if p.MatchString(source) {
			return true
		}
	}
	return false
}

func (d *StorageGapMissingDetector) collectStateVars(
	c *contractBlock,
) []string {

	var stateVars []string
	braceDepth := 0

	for _, line := range c.lines {
		trimmed := strings.TrimSpace(line)
		currentDepth := braceDepth

		if currentDepth == 1 &&
			!regexp.MustCompile(`^\s*(?:function|modifier|struct|enum|constructor)\b`).MatchString(line) {
			excluded := false
			for _, ep := range d.excludePatterns {
				if ep.MatchString(trimmed) {
					excluded = true
					break
				}
			}
			if !excluded {
				for _, p := range d.stateVarPatterns {
					if p.MatchString(trimmed) {
						stateVars = append(stateVars, trimmed)
						break
					}
				}
			}
		}

		for _, ch := range line {
			switch ch {
			case '{':
				braceDepth++
			case '}':
				braceDepth--
			}
		}
		if braceDepth < 0 {
			braceDepth = 0
		}
	}

	return stateVars
}

func (d *StorageGapMissingDetector) isBaseLike(
	fullSource string,
	c *contractBlock,
) bool {

	contractSource := strings.Join(c.lines, "\n")

	if c.isAbstract {
		return true
	}

	for _, signal := range d.baseContractSignals {
		if signal.MatchString(contractSource) {
			return true
		}
	}

	inheritPattern := regexp.MustCompile(
		`\bis\s+(?:\w+,\s*)*` + regexp.QuoteMeta(c.name) + `\b`,
	)
	return inheritPattern.MatchString(fullSource)
}

func (d *StorageGapMissingDetector) buildFinding(
	c *contractBlock,
	filepath string,
	baseLike bool,
	stateVars []string,
) analyzer.Finding {

	shown := stateVars
	suffix := ""
	if len(stateVars) > 3 {
		shown = stateVars[:3]
		suffix = "\n  ..."
	}
	varList := strings.Join(shown, "\n  ") + suffix

	var title, description string

	if baseLike {
		title = "Consider adding __gap to '" + c.name + "'"
		description = "'" + c.name + "' is an upgradeable contract that appears to be a base " +
			"contract or is inherited by other contracts in this project. If a new state variable " +
			"is added to this contract in a future upgrade, storage slots in child contracts may shift.\n\n" +
			"State variables found:\n  " + varList + "\n\n" +
			"Consider: uint256[N] private __gap; where N = 50 minus the number of storage slots used.\n\n" +
			"Note: if you are using EIP-7201 namespaced storage or this contract will never have " +
			"new state variables added, __gap is not required."
	} else {
		title = "Upgradeable contract '" + c.name + "' missing __gap"
		description = "'" + c.name + "' is upgradeable and has state variables but no __gap. " +
			"If this contract is ever used as a base or receives new state variables in a future " +
			"upgrade, storage layout issues may arise in inheriting contracts.\n\n" +
			"State variables found:\n  " + varList + "\n\n" +
			"This is informational. __gap is only required if the contract is intended to be " +
			"inherited or upgraded with new storage variables."
	}

	finding := detectorFinding(rules.IDInit003, filepath, c.startLine, "contract "+c.name+" { ... }")
	finding.Title = title
	finding.Description = description
	finding.Severity = analyzer.Low
	finding.Confidence = analyzer.ConfidenceLow
	return finding
}
