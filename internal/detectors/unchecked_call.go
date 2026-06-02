package detectors

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/ayb-blc/solsec/internal/analyzer"
)

type UncheckedCallDetector struct {
	uncheckedCallPatterns []*regexp.Regexp

	checkedPatterns []*regexp.Regexp

	requireCallPattern *regexp.Regexp
}

func NewUncheckedCallDetector() *UncheckedCallDetector {
	return &UncheckedCallDetector{
		uncheckedCallPatterns: []*regexp.Regexp{
			regexp.MustCompile(`^\s*\w[\w\.\[\]]*\s*\.\s*call\s*[\({]`),
			regexp.MustCompile(`^\s*\w[\w\.\[\]]*\s*\.\s*send\s*\(`),
		},

		checkedPatterns: []*regexp.Regexp{
			// (bool success, ...) = addr.call(...)
			regexp.MustCompile(`\(\s*bool\s+\w+`),
			// bool sent = addr.send(...)
			regexp.MustCompile(`bool\s+\w+\s*=`),
			regexp.MustCompile(`^\s*return\s+`),
		},

		requireCallPattern: regexp.MustCompile(
			`require\s*\(\s*\w[\w\.\[\]]*\s*\.\s*(call|send)\s*\(`,
		),
	}
}

func (d *UncheckedCallDetector) Name() string                { return "unchecked-call" }
func (d *UncheckedCallDetector) Severity() analyzer.Severity { return analyzer.High }
func (d *UncheckedCallDetector) Description() string {
	return "Detects external calls whose return values are not checked"
}

func (d *UncheckedCallDetector) Analyze(
	lines []string,
	source string,
	filepath string,
) ([]analyzer.Finding, error) {
	var findings []analyzer.Finding

	for i, line := range lines {
		lineNum := i + 1

		if d.requireCallPattern.MatchString(line) {
			continue
		}

		isChecked := false
		for _, cp := range d.checkedPatterns {
			if cp.MatchString(line) {
				isChecked = true
				break
			}
		}
		if isChecked {
			continue
		}

		for _, pattern := range d.uncheckedCallPatterns {
			if !pattern.MatchString(line) {
				continue
			}

			callType := "call"
			if strings.Contains(line, ".send(") {
				callType = "send"
			}

			// Severity belirleme:
			severity := analyzer.High
			if callType == "send" {
				severity = analyzer.Medium
			}

			snippet := strings.TrimSpace(line)

			findings = append(findings, analyzer.Finding{
				DetectorName: d.Name(),
				Title: fmt.Sprintf(
					"Unchecked return value of .%s() at line %d",
					callType, lineNum,
				),
				Description: fmt.Sprintf(
					"The return value of '.%s()' is not checked. "+
						"If the call fails, execution continues silently. "+
						"This can lead to inconsistent state: balances updated but ETH not transferred.",
					callType,
				),
				Recommendation: d.buildRecommendation(callType, snippet),
				Filepath:       filepath,
				Line:           lineNum,
				CodeSnippet:    snippet,
				Severity:       severity,
				Confidence:     analyzer.ConfidenceHigh,
				Tags:           []string{"unchecked-call", "return-value", callType},
			})
			break
		}
	}

	return findings, nil
}

func (d *UncheckedCallDetector) buildRecommendation(callType, snippet string) string {
	switch callType {
	case "call":
		return fmt.Sprintf(
			"Always check the return value of .call():\n"+
				"  // Before:\n"+
				"  %s\n\n"+
				"  // After:\n"+
				"  (bool success, bytes memory data) = %s\n"+
				"  require(success, \"External call failed\");",
			snippet, snippet,
		)
	case "send":
		return "Replace .send() with .call() and check the return value:\n" +
			"  // send() has 2300 gas limit which may cause issues\n" +
			"  (bool success,) = recipient.call{value: amount}(\"\");\n" +
			"  require(success, \"ETH transfer failed\");"
	default:
		return "Check all return values from external calls."
	}
}
