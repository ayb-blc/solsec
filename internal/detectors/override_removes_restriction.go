package detectors

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/ayb-blc/solsec/internal/analyzer"
	"github.com/ayb-blc/solsec/internal/inheritancegraph"
	"github.com/ayb-blc/solsec/internal/rules"
)

// OverrideRemovesRestrictionDetector detects overrides that remove access
// restrictions from a parent function.
type OverrideRemovesRestrictionDetector struct {
	contractStart *regexp.Regexp
	accessMods    *regexp.Regexp
}

type overrideContract struct {
	name        string
	lines       []string
	startLine   int
	header      string
	bases       []string
	isInterface bool
	functions   map[string][]*overrideFunction
}

type overrideFunction struct {
	name        string
	signature   string
	lines       []string
	startLine   int
	paramCount  int
	modifiers   []string
	visibility  string
	mutability  string
	hasOverride bool
}

func NewOverrideRemovesRestrictionDetector() *OverrideRemovesRestrictionDetector {
	return &OverrideRemovesRestrictionDetector{
		contractStart: regexp.MustCompile(`^\s*(?:(interface|abstract\s+contract|contract)\s+)(\w+)(?:\s+is\s+([^{]+))?`),
		accessMods: regexp.MustCompile(
			`(?i)\b(onlyOwner|onlyAdmin|onlyRole|onlyGovernor|onlyGuardian|onlyOperator|onlyMinter|` +
				`onlyPoolAdmin|onlyEmergencyAdmin|requiresAuth|auth|restricted|protected|adminOnly|ifAdmin)\b`,
		),
	}
}

func (d *OverrideRemovesRestrictionDetector) Name() string { return "override-removes-restriction" }

func (d *OverrideRemovesRestrictionDetector) Severity() analyzer.Severity {
	return analyzer.High
}

func (d *OverrideRemovesRestrictionDetector) Description() string {
	return "Detects overrides that drop parent access-control restrictions"
}

func (d *OverrideRemovesRestrictionDetector) Analyze(
	lines []string,
	source string,
	filepath string,
) ([]analyzer.Finding, error) {
	contracts := d.extractContracts(lines)
	byName := make(map[string]*overrideContract, len(contracts))
	for _, contract := range contracts {
		contract.functions = d.extractContractFunctions(contract)
		byName[contract.name] = contract
	}

	var findings []analyzer.Finding
	for _, child := range contracts {
		if child.isInterface {
			continue
		}
		for _, funcs := range child.functions {
			for _, childFn := range funcs {
				if !childFn.hasOverride {
					continue
				}
				if d.shouldSkipChildFunction(childFn) {
					continue
				}
				if d.hasAccessRestriction(childFn, lines) {
					continue
				}

				for _, parentName := range child.bases {
					parentFn, parent := d.findInParentChain(parentName, childFn.name, childFn.paramCount, byName, nil)
					if parentFn == nil {
						continue
					}
					if !d.hasAccessRestriction(parentFn, lines) || d.hasAccessRestriction(childFn, lines) {
						continue
					}

					severity := analyzer.High
					confidence := analyzer.ConfidenceHigh
					if overrideFunctionWritesState(childFn.lines) {
						severity = analyzer.Critical
					}
					findings = append(findings, d.buildFinding(filepath, child, parent, childFn, severity, confidence))
				}
			}
		}
	}

	return findings, nil
}

// AnalyzeWithIndex analyzes override regressions using project-level override
// tracking. It supports cross-file inheritance and body-aware modifier
// resolution.
func (d *OverrideRemovesRestrictionDetector) AnalyzeWithIndex(
	filepath string,
	idx *inheritancegraph.ProjectOverrideIndex,
	graph *inheritancegraph.Graph,
) ([]analyzer.Finding, error) {
	if idx == nil || graph == nil {
		return nil, nil
	}

	var findings []analyzer.Finding
	for _, report := range idx.FindAllRegressions() {
		if report.RegressionLink == nil ||
			report.RegressionLink.Contract == nil ||
			report.RegressionLink.Function == nil ||
			report.DroppedDef == nil {
			continue
		}
		if report.RegressionLink.Contract.Filepath != filepath {
			continue
		}

		severity := analyzer.High
		if overrideFunctionWritesState(report.RegressionLink.Function.BodyLines) {
			severity = analyzer.Critical
		}

		rootLink := report.Chain.Root()
		if rootLink == nil || rootLink.Contract == nil {
			continue
		}

		fn := report.RegressionLink.Function
		contract := report.RegressionLink.Contract
		finding := detectorFinding(rules.IDInit005, filepath, fn.LineNumber, strings.TrimSpace(fn.Signature))
		finding.Title = fmt.Sprintf(
			"Override '%s.%s' drops '%s' from '%s'",
			contract.Name,
			report.Chain.FunctionName,
			report.DroppedDef.Name,
			rootLink.Contract.Name,
		)
		finding.Description = fmt.Sprintf(
			"Function '%s' was first defined in '%s' with access control modifier '%s'.\n\n"+
				"The override in '%s' drops this modifier. Override chain depth: %d.",
			report.Chain.FunctionName,
			rootLink.Contract.Name,
			report.DroppedDef.Name,
			contract.Name,
			report.Chain.Depth(),
		)
		finding.Severity = severity
		finding.Confidence = analyzer.ConfidenceHigh
		finding.Tags = appendUniqueStrings(finding.Tags, "override", "inheritance", "access-control", "project-context")
		findings = append(findings, finding)
	}

	return findings, nil
}

func (d *OverrideRemovesRestrictionDetector) extractContracts(lines []string) []*overrideContract {
	var blocks []*overrideContract
	var current *overrideContract
	var headerLines []string
	depth := 0
	headerDepth := 0

	for i, line := range lines {
		lineNum := i + 1

		if current == nil {
			if headerLines == nil {
				if !regexp.MustCompile(`^\s*(?:interface|abstract\s+contract|contract)\s+\w+`).MatchString(line) {
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

			kind := strings.TrimSpace(m[1])
			current = &overrideContract{
				name:        m[2],
				header:      strings.TrimSpace(header),
				startLine:   lineNum - len(headerLines) + 1,
				lines:       append([]string(nil), headerLines...),
				isInterface: kind == "interface",
			}
			if len(m) > 3 {
				current.bases = parseBaseContracts(m[3])
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

func (d *OverrideRemovesRestrictionDetector) extractContractFunctions(contract *overrideContract) map[string][]*overrideFunction {
	functions := make(map[string][]*overrideFunction)
	for _, fn := range extractFunctions(contract.lines) {
		signature := joinFunctionSignatureLines(fn.lines)
		ofn := &overrideFunction{
			name:        fn.name,
			signature:   signature,
			lines:       fn.lines,
			startLine:   contract.startLine + fn.startLine - 1,
			paramCount:  countFunctionParams(signature),
			modifiers:   extractAccessRelevantModifiers(signature),
			visibility:  extractVisibility(signature),
			mutability:  extractMutability(signature),
			hasOverride: regexp.MustCompile(`\boverride\b`).MatchString(signature),
		}
		functions[ofn.name] = append(functions[ofn.name], ofn)
	}
	return functions
}

func (d *OverrideRemovesRestrictionDetector) findFunction(contract *overrideContract, name string, params int) *overrideFunction {
	for _, fn := range contract.functions[name] {
		if fn.paramCount == params {
			return fn
		}
	}
	return nil
}

func (d *OverrideRemovesRestrictionDetector) findInParentChain(
	parentName string,
	functionName string,
	params int,
	byName map[string]*overrideContract,
	visited map[string]bool,
) (*overrideFunction, *overrideContract) {
	if visited == nil {
		visited = make(map[string]bool)
	}
	if visited[parentName] {
		return nil, nil
	}
	visited[parentName] = true

	parent, ok := byName[parentName]
	if !ok || parent.isInterface {
		return nil, nil
	}
	if fn := d.findFunction(parent, functionName, params); fn != nil {
		return fn, parent
	}
	for _, nextParent := range parent.bases {
		if fn, contract := d.findInParentChain(nextParent, functionName, params, byName, visited); fn != nil {
			return fn, contract
		}
	}
	return nil, nil
}

func (d *OverrideRemovesRestrictionDetector) hasAccessRestriction(fn *overrideFunction, lines []string) bool {
	for _, mod := range fn.modifiers {
		if d.accessMods.MatchString(mod) {
			return true
		}
	}
	return d.rawSignatureHasAccessControl(lines, fn.startLine)
}

func (d *OverrideRemovesRestrictionDetector) shouldSkipChildFunction(fn *overrideFunction) bool {
	return fn.mutability == "view" || fn.mutability == "pure"
}

func (d *OverrideRemovesRestrictionDetector) buildFinding(
	filepath string,
	child *overrideContract,
	parent *overrideContract,
	fn *overrideFunction,
	severity analyzer.Severity,
	confidence analyzer.Confidence,
) analyzer.Finding {
	finding := detectorFinding(rules.IDInit005, filepath, fn.startLine, strings.TrimSpace(fn.signature))
	finding.Title = "Override removes access restriction"
	finding.Description = fmt.Sprintf(
		"Function '%s.%s' overrides '%s.%s' but does not keep an access-control modifier. "+
			"If the parent function was restricted, this override can expose privileged behavior.",
		child.name, fn.name, parent.name, fn.name,
	)
	finding.Severity = severity
	finding.Confidence = confidence
	finding.Tags = appendUniqueStrings(finding.Tags, "override", "inheritance", "access-control")
	return finding
}

func (d *OverrideRemovesRestrictionDetector) rawSignatureHasAccessControl(lines []string, lineNum int) bool {
	start := lineNum - 1
	if start < 0 {
		start = 0
	}
	end := start + 8
	if end > len(lines) {
		end = len(lines)
	}

	for _, line := range lines[start:end] {
		if d.accessMods.MatchString(line) {
			return true
		}
		if strings.Contains(line, "{") {
			break
		}
	}
	return false
}

func extractAccessRelevantModifiers(signature string) []string {
	clean := regexp.MustCompile(`\([^)]*\)`).ReplaceAllString(signature, "()")
	words := regexp.MustCompile(`\b[A-Za-z_]\w*\b`).FindAllString(clean, -1)
	keywords := map[string]bool{
		"function": true, "returns": true, "public": true, "external": true,
		"internal": true, "private": true, "pure": true, "view": true,
		"payable": true, "virtual": true, "override": true, "memory": true,
		"storage": true, "calldata": true,
	}
	var mods []string
	for i, word := range words {
		if i == 1 {
			continue
		}
		if keywords[word] || strings.HasPrefix(word, "uint") || strings.HasPrefix(word, "int") ||
			strings.HasPrefix(word, "bytes") || word == "address" || word == "bool" ||
			word == "string" {
			continue
		}
		mods = append(mods, word)
	}
	return mods
}

func joinFunctionSignatureLines(lines []string) string {
	var parts []string
	for _, line := range lines {
		parts = append(parts, strings.TrimSpace(line))
		if strings.Contains(line, "{") {
			break
		}
	}
	return strings.Join(parts, " ")
}

func countFunctionParams(signature string) int {
	start := strings.Index(signature, "(")
	if start < 0 {
		return 0
	}
	depth := 0
	for i := start; i < len(signature); i++ {
		switch signature[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				params := strings.TrimSpace(signature[start+1 : i])
				if params == "" {
					return 0
				}
				count := 1
				for _, ch := range params {
					if ch == ',' {
						count++
					}
				}
				return count
			}
		}
	}
	return 0
}

func overrideFunctionWritesState(lines []string) bool {
	if hasInitializerStateWrite(lines) {
		return true
	}

	assignRe := regexp.MustCompile(`\b[A-Za-z_]\w*(?:\s*\[[^\]]+\])?\s*(?:=|\+=|-=|\*=|/=)\s*[^=]`)
	declarationRe := regexp.MustCompile(`\b(?:bool|address|string|bytes\d*|u?int\d*|[A-Z]\w*)\s+\w+\s*=`)
	for _, line := range lines {
		line = stripLineComments(line)
		open := strings.Index(line, "{")
		close := strings.LastIndex(line, "}")
		if open >= 0 && close > open {
			line = line[open+1 : close]
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "return ") || declarationRe.MatchString(trimmed) {
			continue
		}
		if assignRe.MatchString(trimmed) {
			return true
		}
	}
	return false
}
