package detectors

import (
	"regexp"
	"strings"

	"github.com/ayb-blc/solsec/internal/analyzer"
	"github.com/ayb-blc/solsec/internal/rules"
)

// UninitializedOwnableDetector detects OwnableUpgradeable contracts whose
// initializer never initializes ownership.
type UninitializedOwnableDetector struct {
	contractStart *regexp.Regexp
}

type ownableContractBlock struct {
	name      string
	lines     []string
	startLine int
	header    string
	bases     []string
}

func NewUninitializedOwnableDetector() *UninitializedOwnableDetector {
	return &UninitializedOwnableDetector{
		contractStart: regexp.MustCompile(`^\s*(?:abstract\s+)?contract\s+(\w+)(?:\s+is\s+([^{]+))?`),
	}
}

func (d *UninitializedOwnableDetector) Name() string { return "uninitialized-ownable" }

func (d *UninitializedOwnableDetector) Severity() analyzer.Severity {
	return analyzer.High
}

func (d *UninitializedOwnableDetector) Description() string {
	return "Detects OwnableUpgradeable contracts that do not initialize ownership"
}

func (d *UninitializedOwnableDetector) Analyze(
	lines []string,
	source string,
	filepath string,
) ([]analyzer.Finding, error) {
	contracts := d.extractContracts(lines)
	if len(contracts) == 0 {
		return nil, nil
	}

	var findings []analyzer.Finding
	for _, contract := range contracts {
		if !d.inheritsOwnableUpgradeable(contract) {
			continue
		}
		if d.ownershipInitialized(contract) {
			continue
		}

		finding := detectorFinding(rules.IDInit004, filepath, contract.startLine, strings.TrimSpace(contract.header))
		finding.Title = "OwnableUpgradeable contract does not initialize ownership"
		finding.Description = "Contract '" + contract.name + "' inherits OwnableUpgradeable, but no initializer " +
			"calls __Ownable_init(), __Ownable_init_unchained(), or _transferOwnership(). " +
			"The owner may remain unset, which can permanently break onlyOwner administration or leave setup incomplete."
		finding.Severity = analyzer.High
		finding.Confidence = analyzer.ConfidenceHigh
		finding.Tags = appendUniqueStrings(finding.Tags, "ownable", "upgradeable", "initialization")
		findings = append(findings, finding)
	}

	return findings, nil
}

func (d *UninitializedOwnableDetector) extractContracts(lines []string) []*ownableContractBlock {
	var blocks []*ownableContractBlock
	var current *ownableContractBlock
	depth := 0
	headerDepth := 0
	var headerLines []string

	for i, line := range lines {
		lineNum := i + 1

		if current == nil {
			if headerLines == nil {
				if !regexp.MustCompile(`^\s*(?:abstract\s+)?contract\s+\w+`).MatchString(line) {
					continue
				}
				headerLines = []string{line}
				headerDepth = countParens(line)
			} else {
				headerLines = append(headerLines, line)
				headerDepth += countParens(line)
			}

			header := strings.Join(headerLines, " ")
			if !strings.Contains(header, "{") && headerDepth > 0 {
				continue
			}
			if !strings.Contains(header, "{") {
				continue
			}

			m := d.contractStart.FindStringSubmatch(header)
			if m == nil {
				headerLines = nil
				headerDepth = 0
				continue
			}

			current = &ownableContractBlock{
				name:      m[1],
				header:    strings.TrimSpace(header),
				startLine: lineNum - len(headerLines) + 1,
				lines:     append([]string(nil), headerLines...),
			}
			if len(m) > 2 {
				current.bases = parseBaseContracts(m[2])
			}

			depth = 0
			for _, headerLine := range headerLines {
				depth += countBraces(headerLine)
			}
			headerLines = nil
			headerDepth = 0

			if depth <= 0 {
				blocks = append(blocks, current)
				current = nil
			}
			continue
		}

		current.lines = append(current.lines, line)
		depth += countBraces(line)
		if depth <= 0 {
			blocks = append(blocks, current)
			current = nil
		}
	}

	return blocks
}

func (d *UninitializedOwnableDetector) inheritsOwnableUpgradeable(contract *ownableContractBlock) bool {
	for _, base := range contract.bases {
		if base == "OwnableUpgradeable" || strings.HasSuffix(base, ".OwnableUpgradeable") {
			return true
		}
	}
	return false
}

func (d *UninitializedOwnableDetector) ownershipInitialized(contract *ownableContractBlock) bool {
	source := stripLineComments(strings.Join(contract.lines, "\n"))
	initPatterns := []*regexp.Regexp{
		regexp.MustCompile(`\b__Ownable_init\s*\(`),
		regexp.MustCompile(`\b__Ownable_init_unchained\s*\(`),
		regexp.MustCompile(`\b_transferOwnership\s*\(`),
		regexp.MustCompile(`\btransferOwnership\s*\(`),
	}
	for _, pattern := range initPatterns {
		if pattern.MatchString(source) {
			return true
		}
	}
	return false
}

func parseBaseContracts(raw string) []string {
	raw = strings.TrimSpace(strings.TrimSuffix(raw, "{"))
	if raw == "" {
		return nil
	}

	parts := strings.Split(raw, ",")
	bases := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		part = regexp.MustCompile(`\([^)]*\)`).ReplaceAllString(part, "")
		fields := strings.Fields(part)
		if len(fields) == 0 {
			continue
		}
		bases = append(bases, fields[0])
	}
	return bases
}

func stripLineComments(source string) string {
	lines := strings.Split(source, "\n")
	for i, line := range lines {
		if idx := strings.Index(line, "//"); idx >= 0 {
			lines[i] = line[:idx]
		}
	}
	return strings.Join(lines, "\n")
}

func countBraces(line string) int {
	depth := 0
	for _, ch := range line {
		switch ch {
		case '{':
			depth++
		case '}':
			depth--
		}
	}
	return depth
}

func countParens(line string) int {
	depth := 0
	for _, ch := range line {
		switch ch {
		case '(':
			depth++
		case ')':
			depth--
		}
	}
	return depth
}
