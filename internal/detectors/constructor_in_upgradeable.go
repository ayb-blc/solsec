package detectors

import (
	"regexp"
	"strings"

	"github.com/ayb-blc/solsec/internal/analyzer"
	"github.com/ayb-blc/solsec/internal/rules"
)

// ConstructorInUpgradeableDetector detects constructor state writes in upgradeable contracts.
//
// Safe patterns:
//
//	constructor() { _disableInitializers(); }
//	constructor() {}
//
// Critical patterns:
//
//	constructor(address o) { owner = o; }
//	constructor() { _transferOwnership(msg.sender); }
//	constructor() { grantRole(DEFAULT_ADMIN_ROLE, msg.sender); }
//
// High severity patterns:
//
//	constructor() { fee = 100; maxDeposit = 1e18; }
type ConstructorInUpgradeableDetector struct {
	upgradeableSignals []*regexp.Regexp

	safeConstructorBody []*regexp.Regexp

	criticalPatterns []*regexp.Regexp

	stateWritePatterns []*regexp.Regexp

	constructorStart *regexp.Regexp
}

func NewConstructorInUpgradeableDetector() *ConstructorInUpgradeableDetector {
	return &ConstructorInUpgradeableDetector{

		upgradeableSignals: []*regexp.Regexp{
			regexp.MustCompile(`\bInitializable\b`),
			regexp.MustCompile(`\w+Upgradeable\b`),
			regexp.MustCompile(`\w+Upgradable\b`),
			regexp.MustCompile(`\bfunction\s+initialize\s*\(`),
			regexp.MustCompile(`\b__gap\b`),
			regexp.MustCompile(`__\w+_init\s*\(`),
		},

		safeConstructorBody: []*regexp.Regexp{
			regexp.MustCompile(`_disableInitializers\s*\(\s*\)`),
			regexp.MustCompile(`\bdisableInitializers\s*\(\s*\)`),
		},

		criticalPatterns: []*regexp.Regexp{
			regexp.MustCompile(`\b_?owner\s*=`),
			regexp.MustCompile(`\b_?admin\s*=`),
			regexp.MustCompile(`\b_?governance\s*=`),
			regexp.MustCompile(`\b_?controller\s*=`),
			regexp.MustCompile(`_transferOwnership\s*\(`),
			regexp.MustCompile(`transferOwnership\s*\(`),
			regexp.MustCompile(`__Ownable_init\s*\(`),
			regexp.MustCompile(`__AccessControl_init\s*\(`),
			regexp.MustCompile(`\b_?token\s*=`),
			regexp.MustCompile(`\b_?treasury\s*=`),
			regexp.MustCompile(`\b_?oracle\s*=`),
			regexp.MustCompile(`\b_?implementation\s*=`),
			regexp.MustCompile(`\b_?vault\s*=`),
			regexp.MustCompile(`\b_?pool\s*=`),
			regexp.MustCompile(`\b_?router\s*=`),
			regexp.MustCompile(`\b_?weth\s*=`),
			regexp.MustCompile(`\b_?factory\s*=`),
			regexp.MustCompile(`grantRole\s*\(`),
			regexp.MustCompile(`_grantRole\s*\(`),
			regexp.MustCompile(`_setupRole\s*\(`),
			regexp.MustCompile(`\b_mint\s*\(`),
			regexp.MustCompile(`\b_safeMint\s*\(`),
		},

		stateWritePatterns: []*regexp.Regexp{
			regexp.MustCompile(`\b[a-z_]\w*\s*=\s*[^=]`),
			regexp.MustCompile(`\b\w+\s*\[\s*\w+\s*\]\s*=`),
			regexp.MustCompile(`\b\w+\.\w+\s*=`),
		},

		constructorStart: regexp.MustCompile(`^\s*constructor\s*\(`),
	}
}

func (d *ConstructorInUpgradeableDetector) Name() string {
	return "constructor-in-upgradeable"
}
func (d *ConstructorInUpgradeableDetector) Severity() analyzer.Severity {
	return analyzer.High
}
func (d *ConstructorInUpgradeableDetector) Description() string {
	return "Detects state writes in constructors of upgradeable contracts"
}

func (d *ConstructorInUpgradeableDetector) Analyze(
	lines []string,
	source string,
	filepath string,
) ([]analyzer.Finding, error) {

	if !d.isUpgradeable(source) {
		return nil, nil
	}

	constructors := d.extractConstructors(lines)
	if len(constructors) == 0 {
		return nil, nil
	}

	var findings []analyzer.Finding

	for _, ctor := range constructors {
		if d.isSafeConstructor(ctor) {
			continue
		}

		severity, snippet := d.classifyBody(ctor)
		if severity == analyzer.Info {
			continue
		}

		finding := d.buildFinding(ctor, filepath, severity, snippet)
		findings = append(findings, finding)
	}

	return findings, nil
}

func (d *ConstructorInUpgradeableDetector) isUpgradeable(source string) bool {
	for _, signal := range d.upgradeableSignals {
		if signal.MatchString(source) {
			return true
		}
	}
	return false
}

type constructorBlock struct {
	lines     []string
	startLine int
	signature string
}

func (d *ConstructorInUpgradeableDetector) extractConstructors(
	lines []string,
) []*constructorBlock {

	var ctors []*constructorBlock
	var current *constructorBlock
	depth := 0

	for i, line := range lines {
		lineNum := i + 1

		if current == nil {
			if d.constructorStart.MatchString(line) {
				current = &constructorBlock{
					startLine: lineNum,
					signature: strings.TrimSpace(line),
					lines:     []string{line},
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
					ctors = append(ctors, current)
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
		if depth <= 0 && len(current.lines) > 0 {
			ctors = append(ctors, current)
			current = nil
		}
	}

	return ctors
}

func (d *ConstructorInUpgradeableDetector) isSafeConstructor(ctor *constructorBlock) bool {
	var meaningfulLines []string
	for _, line := range ctor.lines {
		trimmed := normalizeConstructorLine(line)
		if trimmed == "" || trimmed == "{" || trimmed == "}" ||
			strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*") {
			continue
		}
		meaningfulLines = append(meaningfulLines, trimmed)
	}

	if len(meaningfulLines) == 0 {
		return true
	}

	for _, line := range meaningfulLines {
		isSafe := false
		for _, sp := range d.safeConstructorBody {
			if sp.MatchString(line) {
				isSafe = true
				break
			}
		}
		if !isSafe {
			return false
		}
	}

	return true
}

func (d *ConstructorInUpgradeableDetector) classifyBody(
	ctor *constructorBlock,
) (analyzer.Severity, string) {

	for _, line := range ctor.lines {
		trimmed := normalizeConstructorLine(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*") {
			continue
		}

		for _, p := range d.criticalPatterns {
			if p.MatchString(trimmed) {
				return analyzer.Critical, trimmed
			}
		}
	}

	for _, line := range ctor.lines {
		trimmed := normalizeConstructorLine(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*") {
			continue
		}
		if strings.HasPrefix(trimmed, "emit ") ||
			strings.HasPrefix(trimmed, "require(") ||
			strings.HasPrefix(trimmed, "revert ") {
			continue
		}
		for _, p := range d.stateWritePatterns {
			if p.MatchString(trimmed) {
				return analyzer.High, trimmed
			}
		}
	}

	return analyzer.Info, ""
}

func (d *ConstructorInUpgradeableDetector) buildFinding(
	ctor *constructorBlock,
	filepath string,
	severity analyzer.Severity,
	snippet string,
) analyzer.Finding {

	var title, description string

	switch severity {
	case analyzer.Critical:
		title = "Constructor sets critical state in upgradeable contract — state lost on proxy"
		description = "This upgradeable contract's constructor sets critical state " +
			"(owner/admin/token/role). In a proxy deployment, the constructor runs " +
			"on the implementation contract only. The proxy's storage is NEVER set.\n\n" +
			"Result: proxy.owner = address(0), all onlyOwner calls revert forever.\n\n" +
			"Critical operation in constructor:\n  " + snippet + "\n\n" +
			"Fix: Move to initialize() and add 'constructor() { _disableInitializers(); }'"

	case analyzer.High:
		title = "Constructor sets state in upgradeable contract — state invisible to proxy"
		description = "This upgradeable contract's constructor sets state variables. " +
			"In a proxy deployment, the proxy storage is never affected by the " +
			"constructor. Any state written here will appear as zero/default " +
			"when accessed through the proxy.\n\n" +
			"Move all initialization logic to initialize()."
	}

	finding := detectorFinding(rules.IDInit002, filepath, ctor.startLine, ctor.signature)
	finding.Title = title
	finding.Description = description
	finding.Severity = severity
	finding.Confidence = analyzer.ConfidenceHigh
	return finding
}

func normalizeConstructorLine(line string) string {
	trimmed := strings.TrimSpace(line)
	if !strings.HasPrefix(trimmed, "constructor") {
		return trimmed
	}

	open := strings.Index(trimmed, "{")
	if open < 0 {
		return ""
	}
	body := strings.TrimSpace(trimmed[open+1:])
	body = strings.TrimSuffix(body, "}")
	return strings.TrimSpace(body)
}
