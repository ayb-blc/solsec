package detectors

import (
	"regexp"
	"strings"

	"github.com/ayb-blc/solsec/internal/analyzer"
	"github.com/ayb-blc/solsec/internal/rules"
)

// UncheckedCallDetectorV2 detects low-level calls whose return values are not checked.
//
// Safe patterns:
//
//	(bool ok,) = addr.call(...);
//	require(ok);
//
//	bool sent = addr.send(x);
//	require(sent, "failed");
//
//	if (!addr.send(x)) revert();
//
//	require(addr.send(x));
//
// Risky patterns:
//
//	addr.call{value: x}("");
//	addr.send(x);
//	(bool ok,) = addr.call(...);
type UncheckedCallDetectorV2 struct {
	callPattern *regexp.Regexp

	tupleAssignPattern *regexp.Regexp

	boolAssignPattern *regexp.Regexp

	requirePattern *regexp.Regexp

	inlineCheckPattern *regexp.Regexp

	returnedPattern *regexp.Regexp
}

func NewUncheckedCallDetectorV2() *UncheckedCallDetectorV2 {
	return &UncheckedCallDetectorV2{
		callPattern: regexp.MustCompile(
			`\b\w[\w.\[\]]*\s*\.\s*(call|send|delegatecall|staticcall)\s*[\({]`,
		),

		tupleAssignPattern: regexp.MustCompile(
			`\(\s*bool\s+(\w+)`,
		),

		boolAssignPattern: regexp.MustCompile(
			`bool\s+(\w+)\s*=`,
		),

		requirePattern: regexp.MustCompile(
			`(?:require|assert)\s*\(\s*(\w+)`,
		),

		inlineCheckPattern: regexp.MustCompile(
			`(?:require|assert)\s*\(.*\.\s*(?:call|send)\s*[\({]`,
		),

		returnedPattern: regexp.MustCompile(
			`^\s*return\s+.*\.\s*(?:call|send)\s*\(`,
		),
	}
}

func (d *UncheckedCallDetectorV2) Name() string                { return "unchecked-call" }
func (d *UncheckedCallDetectorV2) Severity() analyzer.Severity { return analyzer.High }
func (d *UncheckedCallDetectorV2) Description() string {
	return "Detects external calls whose return values are not checked"
}

func (d *UncheckedCallDetectorV2) Analyze(
	lines []string,
	source string,
	filepath string,
) ([]analyzer.Finding, error) {

	var findings []analyzer.Finding
	fns := extractFunctions(lines)

	for _, fn := range fns {
		fnFindings := d.analyzeFunctionCalls(fn, filepath)
		findings = append(findings, fnFindings...)
	}

	return findings, nil
}

func (d *UncheckedCallDetectorV2) analyzeFunctionCalls(
	fn *fnBlock,
	filepath string,
) []analyzer.Finding {

	var findings []analyzer.Finding

	type callRecord struct {
		lineIdx  int
		snippet  string
		varName  string
		callType string
		checked  bool
	}

	var callRecords []callRecord

	for i, line := range fn.lines {
		if d.inlineCheckPattern.MatchString(line) {
			continue
		}

		if d.returnedPattern.MatchString(line) {
			continue
		}

		// if (!addr.send(x)) revert pattern
		if d.isInlineIfRevert(line) {
			continue
		}

		if !d.callPattern.MatchString(line) {
			continue
		}

		callType := d.extractCallType(line)

		record := callRecord{
			lineIdx:  i,
			snippet:  strings.TrimSpace(line),
			callType: callType,
		}

		if m := d.tupleAssignPattern.FindStringSubmatch(line); len(m) > 1 {
			record.varName = m[1]
		} else if m := d.boolAssignPattern.FindStringSubmatch(line); len(m) > 1 {
			record.varName = m[1]
		} else if varName := d.extractMultilineAssignedBool(fn.lines, i); varName != "" {
			record.varName = varName
		}

		callRecords = append(callRecords, record)
	}

	for i := range callRecords {
		rec := &callRecords[i]

		if rec.varName == "" {
			rec.checked = false
		} else {
			rec.checked = d.isVarChecked(fn.lines, rec.lineIdx, rec.varName)
		}

		if rec.checked {
			continue
		}

		ruleID := rules.IDUncheckedCall001
		if rec.callType == "send" {
			ruleID = rules.IDUncheckedCall002
		}
		finding := detectorFinding(ruleID, filepath, fn.startLine+rec.lineIdx, rec.snippet)
		finding.Title = "Unchecked ." + rec.callType + "() return value in '" + fn.name + "'"
		finding.Description = buildUncheckedCallDescription(rec.callType, rec.varName, rec.snippet)
		finding.Confidence = analyzer.ConfidenceHigh

		findings = append(findings, finding)
	}

	return findings
}

func (d *UncheckedCallDetectorV2) extractMultilineAssignedBool(lines []string, callIdx int) string {
	start := callIdx - 3
	if start < 0 {
		start = 0
	}
	context := strings.Join(lines[start:callIdx+1], "\n")
	if !strings.Contains(context, "=") {
		return ""
	}
	if m := d.tupleAssignPattern.FindStringSubmatch(context); len(m) > 1 {
		return m[1]
	}
	if m := d.boolAssignPattern.FindStringSubmatch(context); len(m) > 1 {
		return m[1]
	}
	return ""
}

// isVarChecked checks whether a captured call result is validated soon after use.
//
//	require(ok)
//	require(ok, "message")
//	assert(ok)
//	if (!ok) revert(...)
//	if (!ok) { revert(); }
//	if (ok == false) revert()
func (d *UncheckedCallDetectorV2) isVarChecked(
	lines []string,
	callIdx int,
	varName string,
) bool {
	const lookAhead = 10

	end := callIdx + lookAhead
	if end > len(lines) {
		end = len(lines)
	}

	requireVarRe := regexp.MustCompile(
		`(?:require|assert)\s*\(\s*` + regexp.QuoteMeta(varName),
	)

	negCheckRe := regexp.MustCompile(
		`if\s*\(\s*!` + regexp.QuoteMeta(varName),
	)

	falseCheckRe := regexp.MustCompile(
		`(?:` + regexp.QuoteMeta(varName) + `\s*==\s*false|false\s*==\s*` + regexp.QuoteMeta(varName) + `)`,
	)

	revertRe := regexp.MustCompile(
		`if\s*\(.*!` + regexp.QuoteMeta(varName) + `.*\)\s*(?:revert|return)`,
	)
	passedToFuncRe := regexp.MustCompile(
		`\b(?:[A-Za-z_]\w*\.)?(?:verify\w*|check\w*|handle\w*|\w*CallResult\w*)\s*\([^)]*\b` + regexp.QuoteMeta(varName) + `\b`,
	)
	returnedRe := regexp.MustCompile(
		`return\s+.*\b` + regexp.QuoteMeta(varName) + `\b`,
	)
	assemblyCheckRe := regexp.MustCompile(
		`\bif\s+eq\s*\(\s*` + regexp.QuoteMeta(varName) + `\s*,\s*0\s*\)`,
	)
	assemblyIsZeroRe := regexp.MustCompile(
		`iszero\s*\(\s*` + regexp.QuoteMeta(varName) + `\s*\)`,
	)
	assemblyStartRe := regexp.MustCompile(`\bassembly\s*(?:\([^)]*\))?\s*\{`)

	inAssembly := false
	for i := callIdx + 1; i < end; i++ {
		line := lines[i]
		if assemblyStartRe.MatchString(line) {
			inAssembly = true
		}
		if inAssembly {
			if assemblyCheckRe.MatchString(line) || assemblyIsZeroRe.MatchString(line) {
				return true
			}
			if strings.Contains(line, "}") {
				inAssembly = false
			}
			continue
		}
		if requireVarRe.MatchString(line) ||
			negCheckRe.MatchString(line) ||
			falseCheckRe.MatchString(line) ||
			revertRe.MatchString(line) ||
			passedToFuncRe.MatchString(line) ||
			returnedRe.MatchString(line) {
			return true
		}
	}

	return false
}

// isInlineIfRevert matches inline failure handling such as if (!addr.send(x)) revert().
func (d *UncheckedCallDetectorV2) isInlineIfRevert(line string) bool {
	return regexp.MustCompile(
		`if\s*\(\s*!.*\.\s*(?:send|call)\s*\(`,
	).MatchString(line)
}

func (d *UncheckedCallDetectorV2) extractCallType(line string) string {
	m := regexp.MustCompile(`\.(call|send|delegatecall|staticcall)\s*[\({]`).FindStringSubmatch(line)
	if len(m) > 1 {
		return m[1]
	}
	return "call"
}

func buildUncheckedCallDescription(callType, varName, _ string) string {
	if varName == "" {
		return "Return value of ." + callType + "() is completely ignored. " +
			"If the call fails, execution continues silently, " +
			"potentially leaving contract state inconsistent."
	}
	return "Return value '" + varName + "' from ." + callType + "() is captured " +
		"but never checked with require() or assert(). " +
		"A failed call will not revert the transaction."
}
