package detectors

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/ayb-blc/solsec/internal/analyzer"
	"github.com/ayb-blc/solsec/internal/rules"
)

type ReentrancyDetectorV2 struct {
	externalCall *regexp.Regexp
	stateWrite   *regexp.Regexp
	internalCall *regexp.Regexp
}

func NewReentrancyDetectorV2() *ReentrancyDetectorV2 {
	return &ReentrancyDetectorV2{
		externalCall: regexp.MustCompile(`\.\s*(call|send|transfer)\s*[\({]`),
		stateWrite: regexp.MustCompile(
			`(?:\w+\s*\[[^\]]+\]|\b\w+)\s*(?:=|\+=|-=|\*=|/=)`,
		),
		internalCall: regexp.MustCompile(`^\s*([A-Za-z_]\w*)\s*\(`),
	}
}

func (d *ReentrancyDetectorV2) Name() string                { return "reentrancy" }
func (d *ReentrancyDetectorV2) Severity() analyzer.Severity { return analyzer.Critical }
func (d *ReentrancyDetectorV2) Description() string {
	return "Detects external interactions before state effects using CEI-aware heuristics"
}

func (d *ReentrancyDetectorV2) Analyze(lines []string, source, filepath string) ([]analyzer.Finding, error) {
	functions := extractFunctions(lines)
	byName := make(map[string]*fnBlock, len(functions))
	for _, fn := range functions {
		byName[fn.name] = fn
	}

	var findings []analyzer.Finding
	for _, fn := range functions {
		if fn.isPureOrView() || d.hasGuard(fn, source) {
			continue
		}
		if finding, ok := d.analyzeFunction(fn, byName, filepath); ok {
			findings = append(findings, finding)
		}
	}
	return findings, nil
}

func (d *ReentrancyDetectorV2) analyzeFunction(
	fn *fnBlock,
	byName map[string]*fnBlock,
	filepath string,
) (analyzer.Finding, bool) {
	firstInteraction := -1
	viaInternal := ""

	for i, line := range fn.lines {
		if d.externalCall.MatchString(line) {
			firstInteraction = i
			break
		}
		if called := d.internalCallName(line); called != "" {
			callee := byName[called]
			if callee != nil && d.functionHasExternalCall(callee) {
				firstInteraction = i
				viaInternal = called
				break
			}
		}
	}
	if firstInteraction < 0 {
		return analyzer.Finding{}, false
	}

	for i := firstInteraction + 1; i < len(fn.lines); i++ {
		line := strings.TrimSpace(fn.lines[i])
		if d.isNoise(line) {
			continue
		}
		if d.isStateWrite(line) {
			finding := detectorFinding(rules.IDReentrancy001, filepath, fn.startLine+i, line)
			finding.Title = fmt.Sprintf("Potential reentrancy in function '%s'", fn.name)
			if viaInternal != "" {
				finding.RuleID = rules.IDReentrancy002
				finding.Rule = rules.Global().MustGet(rules.IDReentrancy002)
				finding.Title = fmt.Sprintf("Potential cross-function reentrancy in '%s' via '%s'", fn.name, viaInternal)
				finding.Severity = analyzer.High
			}
			finding.Description = "External interaction happens before a later state update. This violates the Checks-Effects-Interactions pattern and may allow reentrant execution to observe or reuse stale state."
			finding.Recommendation = "Move state updates before external calls or protect the function with a shared nonReentrant guard."
			finding.Confidence = analyzer.ConfidenceHigh
			return finding, true
		}
	}

	return analyzer.Finding{}, false
}

func (d *ReentrancyDetectorV2) isStateWrite(line string) bool {
	mappingWriteRe := regexp.MustCompile(
		`\b\w+\s*\[\s*\w+(?:\.\w+)?\s*\]\s*(?:=|[-+*/&|^]=)`,
	)
	if mappingWriteRe.MatchString(line) {
		return true
	}

	stateAssignRe := regexp.MustCompile(
		`^\s*_?[a-z]\w*\s*(?:=|[-+*/]=)`,
	)
	if !stateAssignRe.MatchString(line) {
		return false
	}
	if strings.Contains(line, "function") {
		return false
	}

	return !regexp.MustCompile(`\b\w+\s*\(`).MatchString(line)
}

func (d *ReentrancyDetectorV2) hasGuard(fn *fnBlock, source string) bool {
	if fn.hasModifier("nonReentrant") {
		return true
	}
	for _, modifier := range fn.modifiers {
		if strings.Contains(strings.ToLower(modifier), "reentrant") {
			return true
		}
	}
	body := strings.Join(fn.lines, "\n")
	if strings.Contains(body, "require(!locked") && strings.Contains(body, "locked = true") {
		return true
	}
	if strings.Contains(source, "ReentrancyGuard") && strings.Contains(fn.signature, "nonReentrant") {
		return true
	}
	return false
}

func (d *ReentrancyDetectorV2) functionHasExternalCall(fn *fnBlock) bool {
	for _, line := range fn.lines {
		if d.externalCall.MatchString(line) {
			return true
		}
	}
	return false
}

func (d *ReentrancyDetectorV2) internalCallName(line string) string {
	m := d.internalCall.FindStringSubmatch(line)
	if len(m) < 2 {
		return ""
	}
	name := m[1]
	switch name {
	case "require", "assert", "revert", "emit", "return", "if", "for", "while":
		return ""
	default:
		return name
	}
}

func (d *ReentrancyDetectorV2) isNoise(line string) bool {
	return line == "" ||
		strings.HasPrefix(line, "//") ||
		strings.HasPrefix(line, "require(") ||
		strings.HasPrefix(line, "assert(") ||
		strings.HasPrefix(line, "emit ")
}
