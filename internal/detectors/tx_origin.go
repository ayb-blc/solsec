package detectors

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/ayb-blc/solsec/internal/analyzer"
)

// Detection stratejisi:
type TxOriginDetector struct {
	authPatterns []*regexp.Regexp

	safePatterns []*regexp.Regexp
}

func NewTxOriginDetector() *TxOriginDetector {
	return &TxOriginDetector{
		authPatterns: []*regexp.Regexp{
			regexp.MustCompile(`require\s*\(\s*tx\.origin\s*==`),

			regexp.MustCompile(`require\s*\([^)]*==\s*tx\.origin`),

			regexp.MustCompile(`if\s*\(\s*tx\.origin\s*==`),

			regexp.MustCompile(`tx\.origin\s*!=`),

			regexp.MustCompile(`tx\.origin\s*==\s*\w+`),
		},

		safePatterns: []*regexp.Regexp{
			regexp.MustCompile(`tx\.origin\s*==\s*msg\.sender`),
			regexp.MustCompile(`msg\.sender\s*==\s*tx\.origin`),

			regexp.MustCompile(`tx\.origin\s*!=\s*msg\.sender`),
		},
	}
}

func (d *TxOriginDetector) Name() string                { return "tx-origin" }
func (d *TxOriginDetector) Severity() analyzer.Severity { return analyzer.High }
func (d *TxOriginDetector) Description() string {
	return "Detects use of tx.origin for authentication which can be exploited via phishing contracts"
}

func (d *TxOriginDetector) Analyze(lines []string, source, filepath string) ([]analyzer.Finding, error) {
	var findings []analyzer.Finding

	for i, line := range lines {
		lineNum := i + 1
		code := stripLineComment(line)
		if strings.TrimSpace(code) == "" {
			continue
		}

		isSafe := false
		for _, safe := range d.safePatterns {
			if safe.MatchString(code) {
				isSafe = true
				break
			}
		}
		if isSafe {
			continue
		}

		for _, pattern := range d.authPatterns {
			if pattern.MatchString(code) {
				findings = append(findings, analyzer.Finding{
					DetectorName: d.Name(),
					Title:        "Use of tx.origin for authentication",
					Description: fmt.Sprintf(
						"tx.origin is used for access control at line %d. "+
							"This can be exploited if the authorized user is tricked into calling a malicious contract, "+
							"which then calls this contract. The malicious contract becomes msg.sender but tx.origin "+
							"remains the authorized user, bypassing the authentication check.",
						lineNum,
					),
					Recommendation: "Replace tx.origin with msg.sender for authentication. " +
						"If you need to verify the caller is an EOA (not a contract), " +
						"use tx.origin == msg.sender as a check, not tx.origin alone.",
					Filepath:    filepath,
					Line:        lineNum,
					CodeSnippet: strings.TrimSpace(code),
					Severity:    analyzer.High,
					Confidence:  analyzer.ConfidenceHigh,
					Tags:        []string{"tx-origin", "authentication", "phishing", "access-control"},
				})
				break
			}
		}
	}

	return findings, nil
}

func stripLineComment(line string) string {
	if idx := strings.Index(line, "//"); idx >= 0 {
		return line[:idx]
	}
	return line
}
