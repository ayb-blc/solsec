package detectors

import (
	"regexp"
	"strings"

	"github.com/ayb-blc/solsec/internal/analyzer"
	"github.com/ayb-blc/solsec/internal/pathtracker"
	"github.com/ayb-blc/solsec/internal/rules"
)

type ReinitializableInitDetector struct {
	safeGuards []*regexp.Regexp
}

func NewReinitializableInitDetector() *ReinitializableInitDetector {
	return &ReinitializableInitDetector{
		safeGuards: []*regexp.Regexp{
			regexp.MustCompile(`\binitializer\b`),
			regexp.MustCompile(`\breinitializer\s*\(`),
			regexp.MustCompile(`\bonlyInitializing\b`),
			regexp.MustCompile(`\bonlyOwner\b`),
			regexp.MustCompile(`\bonlyAdmin\b`),
			regexp.MustCompile(`\bonlyRole\b`),
			regexp.MustCompile(`\bwhenNotInitialized\b`),
			regexp.MustCompile(`require\s*\(\s*!\s*_?initialized\b`),
			regexp.MustCompile(`require\s*\(\s*!\s*_?isInitialized\b`),
			regexp.MustCompile(`require\s*\(\s*_?initialized\s*==\s*false\b`),
			regexp.MustCompile(`if\s*\(\s*_?initialized\b.*\)\s*(?:revert|return|\{)`),
			regexp.MustCompile(`_disableInitializers\s*\(`),
			regexp.MustCompile(`_implementation\(\)\s*==\s*address\s*\(\s*0\s*\)`),
			regexp.MustCompile(`implementation\s*==\s*address\s*\(\s*0\s*\)`),
			regexp.MustCompile(`require\s*\([^)]*==\s*(?:0|address\s*\(\s*0\s*\))`),
		},
	}
}

func (d *ReinitializableInitDetector) Name() string { return "reinitializable-init" }

func (d *ReinitializableInitDetector) Severity() analyzer.Severity {
	return analyzer.High
}

func (d *ReinitializableInitDetector) Description() string {
	return "Detects public or external initialize() functions that can be called more than once"
}

func (d *ReinitializableInitDetector) Analyze(
	lines []string,
	source string,
	filepath string,
) ([]analyzer.Finding, error) {
	var findings []analyzer.Finding

	for _, fn := range extractFunctions(lines) {
		if fn.name != "initialize" {
			continue
		}
		if isLineInScopeKind(lines, fn.startLine, "interface", "library") {
			continue
		}
		if fn.visibility != "public" && fn.visibility != "external" && fn.visibility != "" {
			continue
		}
		if d.isProtected(fn) {
			continue
		}

		severity, confidence, reason := d.classifyImpact(fn)
		finding := detectorFinding(rules.IDInit001, filepath, fn.startLine, fn.signature)
		finding.Title = "Reinitializable initialize() function"
		finding.Description = "The initialize() function is externally callable and lacks an initializer " +
			"modifier or explicit initialized flag. It can be called multiple times after deployment. " +
			reason
		finding.Severity = severity
		finding.Confidence = confidence
		finding.Tags = appendUniqueStrings(finding.Tags, "initialization", "upgradeable", "proxy")

		findings = append(findings, finding)
	}

	return findings, nil
}

func (d *ReinitializableInitDetector) isProtected(fn *fnBlock) bool {
	inSignature := true
	for _, line := range fn.lines {
		if inSignature {
			for _, guard := range d.safeGuards {
				if guard.MatchString(line) {
					return true
				}
			}
			if strings.Contains(line, "{") {
				inSignature = false
			}
			continue
		}
		break
	}

	inBody := false
	bodyLines := 0
	for _, line := range fn.lines {
		if !inBody {
			if strings.Contains(line, "{") {
				inBody = true
			}
			continue
		}
		bodyLines++
		if bodyLines > 8 {
			break
		}
		for _, guard := range d.safeGuards {
			if guard.MatchString(line) {
				return true
			}
		}
	}

	for _, guard := range pathtracker.New().FindEarlyGuards(functionBodyForPathTracking(fn.lines)) {
		if guard.Kind == pathtracker.GuardInitialized {
			return true
		}
	}

	return false
}

func (d *ReinitializableInitDetector) classifyImpact(fn *fnBlock) (analyzer.Severity, analyzer.Confidence, string) {
	source := strings.Join(fn.lines, "\n")

	criticalPatterns := []*regexp.Regexp{
		regexp.MustCompile(`\b_?(?:owner|admin|governance|guardian|operator|pauser)\b\s*=`),
		regexp.MustCompile(`\b_?(?:token|treasury|oracle|implementation|impl)\b\s*=`),
		regexp.MustCompile(`\b(?:_?mint|grantRole|_grantRole|_setupRole|setupRole)\s*\(`),
		regexp.MustCompile(`\b(?:transferOwnership|_transferOwnership)\s*\(`),
	}
	for _, pattern := range criticalPatterns {
		if pattern.MatchString(source) {
			return analyzer.Critical, analyzer.ConfidenceHigh,
				"The initializer writes privileged state or grants privileged capabilities."
		}
	}

	if hasInitializerStateWrite(fn.lines) {
		return analyzer.High, analyzer.ConfidenceHigh,
			"The initializer writes state variables, so repeated calls can change contract configuration."
	}

	return analyzer.Medium, analyzer.ConfidenceMedium,
		"The initializer body appears minimal, but repeated calls still indicate unsafe initialization design."
}

func hasInitializerStateWrite(lines []string) bool {
	assignmentRe := regexp.MustCompile(`^\s*(?:[A-Za-z_]\w*(?:\s*\[[^\]]+\])?|\w+\.\w+)\s*(?:=|\+=|-=|\*=|/=)`)
	declarationRe := regexp.MustCompile(`^\s*(?:bool|address|string|bytes\d*|u?int\d*|[A-Z]\w*)\s+\w+\s*=`)

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") {
			continue
		}
		if declarationRe.MatchString(trimmed) {
			continue
		}
		if assignmentRe.MatchString(trimmed) {
			return true
		}
	}
	return false
}

func appendUniqueStrings(values []string, items ...string) []string {
	seen := make(map[string]bool, len(values)+len(items))
	for _, value := range values {
		seen[value] = true
	}
	for _, item := range items {
		if !seen[item] {
			values = append(values, item)
			seen[item] = true
		}
	}
	return values
}
