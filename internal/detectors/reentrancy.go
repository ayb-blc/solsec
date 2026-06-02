package detectors

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/ayb-blc/solsec/internal/analyzer"
)

// ReentrancyDetector looks for external-call-before-state-update patterns.
type ReentrancyDetector struct {
	externalCallPatterns []*regexp.Regexp

	// stateChangePatterns matches likely state variable assignments.
	stateChangePatterns []*regexp.Regexp

	guardPatterns []*regexp.Regexp
}

func NewReentrancyDetector() *ReentrancyDetector {
	return &ReentrancyDetector{
		externalCallPatterns: []*regexp.Regexp{
			regexp.MustCompile(`\.call\s*\{[^}]*value\s*:`),

			regexp.MustCompile(`\.call\s*\(`),

			regexp.MustCompile(`\.\s*transfer\s*\(`),

			regexp.MustCompile(`\.\s*send\s*\(`),
		},

		stateChangePatterns: []*regexp.Regexp{
			regexp.MustCompile(`balances\s*\[`),

			regexp.MustCompile(`\w+\s*=\s*0`),

			regexp.MustCompile(`\w+\s*-=\s*`),
		},

		guardPatterns: []*regexp.Regexp{
			regexp.MustCompile(`ReentrancyGuard`),

			regexp.MustCompile(`nonReentrant`),

			regexp.MustCompile(`\blocked\b`),

			regexp.MustCompile(`\bmutex\b`),
		},
	}
}

func (d *ReentrancyDetector) Name() string                { return "reentrancy" }
func (d *ReentrancyDetector) Severity() analyzer.Severity { return analyzer.Critical }
func (d *ReentrancyDetector) Description() string {
	return "Detects potential reentrancy vulnerabilities where external calls precede state updates"
}

func (d *ReentrancyDetector) Analyze(lines []string, source, filepath string) ([]analyzer.Finding, error) {
	var findings []analyzer.Finding

	fileHasGlobalGuard := d.hasGlobalGuard(source)

	functions := d.extractFunctions(lines)

	for _, fn := range functions {
		finding, found := d.analyzeFunction(fn, filepath, fileHasGlobalGuard)
		if found {
			findings = append(findings, finding)
		}
	}

	return findings, nil
}

type solFunction struct {
	name      string
	startLine int
	lines     []string
	hasGuard  bool
}

// Edge case'ler:
func (d *ReentrancyDetector) extractFunctions(lines []string) []solFunction {
	var functions []solFunction
	var currentFn *solFunction
	braceDepth := 0

	fnPattern := regexp.MustCompile(`^\s*function\s+(\w+)\s*\(`)

	guardPattern := regexp.MustCompile(`nonReentrant`)

	for i, line := range lines {
		lineNum := i + 1

		if currentFn == nil {
			if matches := fnPattern.FindStringSubmatch(line); matches != nil {
				currentFn = &solFunction{
					name:      matches[1],
					startLine: lineNum,
					lines:     []string{line},
					hasGuard:  guardPattern.MatchString(line),
				}
				braceDepth = braceDelta(line)
				if braceDepth == 0 {
					functions = append(functions, *currentFn)
					currentFn = nil
				}
			}
		} else {
			currentFn.lines = append(currentFn.lines, line)

			braceDepth += braceDelta(line)

			if braceDepth == 0 && len(currentFn.lines) == 1 {
				if guardPattern.MatchString(line) {
					currentFn.hasGuard = true
				}
			}

			if braceDepth == 0 && len(currentFn.lines) > 0 {
				functions = append(functions, *currentFn)
				currentFn = nil
			}
		}
	}

	return functions
}

func braceDelta(line string) int {
	delta := 0
	for _, ch := range line {
		switch ch {
		case '{':
			delta++
		case '}':
			delta--
		}
	}
	return delta
}

// Detection logic:
func (d *ReentrancyDetector) analyzeFunction(
	fn solFunction,
	filepath string,
	fileHasGlobalGuard bool,
) (analyzer.Finding, bool) {

	if fn.hasGuard || fileHasGlobalGuard {
		return analyzer.Finding{}, false
	}

	externalCallLine := -1
	externalCallCode := ""

	for i, line := range fn.lines {
		for _, pattern := range d.externalCallPatterns {
			if pattern.MatchString(line) {
				externalCallLine = i
				externalCallCode = strings.TrimSpace(line)
				break
			}
		}
		if externalCallLine >= 0 {
			break
		}
	}

	if externalCallLine < 0 {
		return analyzer.Finding{}, false
	}

	stateChangeAfterCall := false
	stateChangeLine := ""

	for i := externalCallLine + 1; i < len(fn.lines); i++ {
		for _, pattern := range d.stateChangePatterns {
			if pattern.MatchString(fn.lines[i]) {
				stateChangeAfterCall = true
				stateChangeLine = strings.TrimSpace(fn.lines[i])
				break
			}
		}
		if stateChangeAfterCall {
			break
		}
	}

	if !stateChangeAfterCall {
		return analyzer.Finding{}, false
	}

	description := fmt.Sprintf(
		"Function '%s' makes an external call ('%s') and then modifies state ('%s'). "+
			"This violates the Checks-Effects-Interactions pattern and is vulnerable to reentrancy attacks.",
		fn.name, externalCallCode, stateChangeLine,
	)
	recommendation := "Apply the Checks-Effects-Interactions pattern: update all state variables " +
		"before making external calls. Consider using OpenZeppelin's ReentrancyGuard."

	return analyzer.Finding{
		DetectorName:   d.Name(),
		Title:          fmt.Sprintf("Potential reentrancy in function '%s'", fn.name),
		Description:    description,
		Recommendation: recommendation,
		Filepath:       filepath,
		Line:           fn.startLine + externalCallLine + 1,
		CodeSnippet:    externalCallCode,
		Severity:       analyzer.Critical,
		Confidence:     analyzer.ConfidenceHigh,
		Tags:           []string{"reentrancy", "external-call", "state-change", "cei-violation"},
	}, true
}

func (d *ReentrancyDetector) hasGlobalGuard(source string) bool {
	for _, pattern := range d.guardPatterns {
		if pattern.MatchString(source) {
			return true
		}
	}
	return false
}
