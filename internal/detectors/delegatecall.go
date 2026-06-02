package detectors

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/ayb-blc/solsec/internal/analyzer"
)

type DelegatecallDetector struct {
	delegatecallPattern *regexp.Regexp

	taintedTargetPatterns []*regexp.Regexp

	accessControlPatterns []*regexp.Regexp

	implementationPatterns []*regexp.Regexp
}

func NewDelegatecallDetector() *DelegatecallDetector {
	return &DelegatecallDetector{
		delegatecallPattern: regexp.MustCompile(`\.delegatecall\s*\(`),

		taintedTargetPatterns: []*regexp.Regexp{
			regexp.MustCompile(`delegatecall\s*\(\s*msg\.data`),
			regexp.MustCompile(`\b(\w+)\s*\.\s*delegatecall`),
		},

		accessControlPatterns: []*regexp.Regexp{
			regexp.MustCompile(`onlyOwner`),
			regexp.MustCompile(`onlyAdmin`),
			regexp.MustCompile(`require\s*\(\s*msg\.sender\s*==`),
			regexp.MustCompile(`require\s*\(\s*.*owner`),
			regexp.MustCompile(`_checkOwner\s*\(`),
			regexp.MustCompile(`hasRole\s*\(`),
		},

		implementationPatterns: []*regexp.Regexp{
			regexp.MustCompile(`\bimplementation\b`),
			regexp.MustCompile(`\bimpl\b`),
			regexp.MustCompile(`\blogic\b`),
			regexp.MustCompile(`\bdelegate\b`),
		},
	}
}

func (d *DelegatecallDetector) Name() string                { return "delegatecall" }
func (d *DelegatecallDetector) Severity() analyzer.Severity { return analyzer.Critical }
func (d *DelegatecallDetector) Description() string {
	return "Detects dangerous delegatecall patterns: unprotected targets, proxy risks, storage collisions"
}

func (d *DelegatecallDetector) Analyze(
	lines []string,
	source string,
	filepath string,
) ([]analyzer.Finding, error) {
	var findings []analyzer.Finding

	if !d.delegatecallPattern.MatchString(source) {
		return nil, nil
	}

	functions := extractFunctionBlocks(lines)

	for _, fn := range functions {
		if fn.visibility == "internal" || fn.visibility == "private" || strings.HasPrefix(fn.name, "_") {
			continue
		}
		findings = append(findings, d.analyzeFunction(fn, filepath, lines)...)
	}

	findings = append(findings, d.checkUnprotectedUpgrade(lines, source, filepath)...)

	return findings, nil
}

func (d *DelegatecallDetector) analyzeFunction(
	fn functionBlock,
	filepath string,
	_ []string,
) []analyzer.Finding {
	var findings []analyzer.Finding

	if fn.name == "initialize" && isOneTimeInitFunction(fn) {
		return nil
	}

	fnSource := strings.Join(fn.lines, "\n")

	if !d.delegatecallPattern.MatchString(fnSource) {
		return nil
	}

	hasAccessControl := false
	for _, pattern := range d.accessControlPatterns {
		if pattern.MatchString(fnSource) {
			hasAccessControl = true
			break
		}
	}

	// Fallback fonksiyonu mu? Proxy pattern'i
	isFallback := fn.name == "fallback" || fn.name == "_fallback" ||
		strings.Contains(fn.signature, "fallback()")

	for i, line := range fn.lines {
		if !d.delegatecallPattern.MatchString(line) {
			continue
		}

		lineNum := fn.startLine + i
		snippet := strings.TrimSpace(line)

		if strings.Contains(line, "msg.data") && isFallback {
			findings = append(findings, analyzer.Finding{
				DetectorName: d.Name(),
				Title: fmt.Sprintf(
					"Proxy delegatecall in fallback of '%s'", fn.contractName,
				),
				Description: "Fallback function uses delegatecall with msg.data. " +
					"Ensure the implementation address can only be set by authorized parties. " +
					"Verify storage layout compatibility between proxy and implementation.",
				Recommendation: "Use OpenZeppelin's TransparentUpgradeableProxy or UUPS pattern. " +
					"Protect implementation slot with EIP-1967 storage slot convention: " +
					"bytes32(uint256(keccak256('eip1967.proxy.implementation')) - 1)",
				Filepath:    filepath,
				Line:        lineNum,
				CodeSnippet: snippet,
				Severity:    analyzer.High,
				Confidence:  analyzer.ConfidenceMedium,
				Tags:        []string{"delegatecall", "proxy", "upgrade"},
			})
			continue
		}

		// Pattern 2: Access control olmayan fonksiyonda delegatecall
		if !hasAccessControl && !isFallback {
			findings = append(findings, analyzer.Finding{
				DetectorName: d.Name(),
				Title: fmt.Sprintf(
					"Unprotected delegatecall in '%s.%s'",
					fn.contractName, fn.name,
				),
				Description: fmt.Sprintf(
					"Function '%s' uses delegatecall without access control. "+
						"Any caller can invoke this with arbitrary calldata, "+
						"potentially taking over the contract's storage.",
					fn.name,
				),
				Recommendation: "Add access control to functions using delegatecall:\n" +
					"  modifier onlyOwner { require(msg.sender == owner); _; }\n" +
					"  function execute(...) external onlyOwner { ... delegatecall ... }",
				Filepath:    filepath,
				Line:        lineNum,
				CodeSnippet: snippet,
				Severity:    analyzer.Critical,
				Confidence:  analyzer.ConfidenceHigh,
				Tags:        []string{"delegatecall", "access-control", "unprotected"},
			})
		}

		targetName := extractDelegatecallTarget(line)
		if targetName != "" && d.isParameterLike(targetName, fn) {
			findings = append(findings, analyzer.Finding{
				DetectorName: d.Name(),
				Title: fmt.Sprintf(
					"User-controlled delegatecall target in '%s.%s'",
					fn.contractName, fn.name,
				),
				Description: fmt.Sprintf(
					"The delegatecall target '%s' appears to be user-controlled. "+
						"An attacker can pass a malicious contract address, "+
						"executing arbitrary code in the context of this contract. "+
						"This allows full storage takeover.",
					targetName,
				),
				Recommendation: fmt.Sprintf(
					"Never use user-supplied addresses as delegatecall targets.\n"+
						"Use a whitelist of approved implementation addresses:\n"+
						"  require(approvedImpls[%s], \"Not approved\");",
					targetName,
				),
				Filepath:    filepath,
				Line:        lineNum,
				CodeSnippet: snippet,
				Severity:    analyzer.Critical,
				Confidence:  analyzer.ConfidenceHigh,
				Tags:        []string{"delegatecall", "tainted-target", "arbitrary-code"},
			})
		}
	}

	return findings
}

func isOneTimeInitFunction(fn functionBlock) bool {
	oneTimePatterns := []*regexp.Regexp{
		regexp.MustCompile(`_implementation\(\)\s*==\s*address\s*\(\s*0\s*\)`),
		regexp.MustCompile(`require\s*\(\s*!\s*_?initialized\b`),
		regexp.MustCompile(`\binitializer\b`),
		regexp.MustCompile(`implementation\s*==\s*address\s*\(\s*0\s*\)`),
	}

	for _, line := range fn.lines {
		for _, pattern := range oneTimePatterns {
			if pattern.MatchString(line) {
				return true
			}
		}
	}
	return false
}

func (d *DelegatecallDetector) checkUnprotectedUpgrade(
	lines []string,
	source string,
	filepath string,
) []analyzer.Finding {
	var findings []analyzer.Finding

	hasImplementationVar := false
	for _, pattern := range d.implementationPatterns {
		if pattern.MatchString(source) {
			hasImplementationVar = true
			break
		}
	}

	if !hasImplementationVar {
		return nil
	}

	functions := extractFunctionBlocks(lines)

	for _, fn := range functions {
		if fn.visibility == "internal" || fn.visibility == "private" || strings.HasPrefix(fn.name, "_") {
			continue
		}

		fnSource := strings.Join(fn.lines, "\n")

		implAssign := false
		for _, pattern := range d.implementationPatterns {
			assignPattern := regexp.MustCompile(
				pattern.String() + `\s*=\s*`,
			)
			if assignPattern.MatchString(fnSource) {
				implAssign = true
				break
			}
		}

		if !implAssign {
			continue
		}

		hasControl := false
		for _, pattern := range d.accessControlPatterns {
			if pattern.MatchString(fnSource) {
				hasControl = true
				break
			}
		}

		if !hasControl && fn.name != "constructor" {
			findings = append(findings, analyzer.Finding{
				DetectorName: d.Name(),
				Title: fmt.Sprintf(
					"Unprotected implementation upgrade in '%s.%s'",
					fn.contractName, fn.name,
				),
				Description: fmt.Sprintf(
					"Function '%s' modifies the implementation/logic address without access control. "+
						"Any user can upgrade the proxy to a malicious implementation.",
					fn.name,
				),
				Recommendation: "Protect upgrade functions with strict access control:\n" +
					"  function upgradeTo(address newImpl) external onlyOwner {\n" +
					"      require(newImpl != address(0));\n" +
					"      implementation = newImpl;\n" +
					"      emit Upgraded(newImpl);\n" +
					"  }",
				Filepath:   filepath,
				Line:       fn.startLine,
				Severity:   analyzer.Critical,
				Confidence: analyzer.ConfidenceHigh,
				Tags:       []string{"delegatecall", "proxy", "unprotected-upgrade"},
			})
		}
	}

	return findings
}

func extractDelegatecallTarget(line string) string {
	pattern := regexp.MustCompile(`(\w+)\s*\.\s*delegatecall\s*\(`)
	matches := pattern.FindStringSubmatch(line)
	if len(matches) >= 2 {
		return matches[1]
	}
	return ""
}

func (d *DelegatecallDetector) isParameterLike(name string, fn functionBlock) bool {
	return strings.Contains(fn.signature, name)
}
