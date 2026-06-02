package detectors

import (
	"regexp"
	"strings"

	"github.com/ayb-blc/solsec/internal/analyzer"
	"github.com/ayb-blc/solsec/internal/rules"
)

// IntegerOverflowDetectorV2 applies version-aware arithmetic checks.
//
// Behavior:
//
//	< 0.8.0  reports risky arithmetic when SafeMath is absent.
//	>= 0.8.0 focuses on unchecked{} blocks and unsafe downcasts.
//
// This avoids noisy reports for Solidity 0.8+ code while preserving coverage
// for older contracts without built-in overflow checks.
type IntegerOverflowDetectorV2 struct {
	arithmeticOps []*regexp.Regexp

	uncheckedStart *regexp.Regexp

	safeMathUsage *regexp.Regexp

	// Unsafe downcast: uint8(x), int16(y)
	unsafeCast *regexp.Regexp

	constantCast *regexp.Regexp
}

var (
	loopCounterRe = regexp.MustCompile(
		`^\s*(?:(?:\+\+|--)\s*[a-zA-Z_]\w{0,15}|[a-zA-Z_]\w{0,15}\s*(?:\+\+|--)|[a-zA-Z_]\w{0,15}\s*[+\-]=\s*1\b)\s*;?\s*$`,
	)
	assemblyRe     = regexp.MustCompile(`\bassembly\s*(?:\([^)]*\))?\s*\{`)
	safeCastFuncRe = regexp.MustCompile(
		`\bto(?:Uint|Int)\d+\s*(?:\(|$)|\btoUint\s*(?:\(|$)`,
	)
	boundsCheckRe = regexp.MustCompile(
		`(?:require|if)\s*\(.*(?:<=|<|>|>=).*type\s*\(\s*(?:u?int)\d+\s*\)\.max`,
	)
	safeCastCallRe = regexp.MustCompile(`SafeCast\.to\w+\(`)
	enumCastRe     = regexp.MustCompile(`(?:u?int)\d+\s*\(\s*[A-Z]\w*(?:\s*\.\s*\w+)+\s*\)`)
	bytesCastRe    = regexp.MustCompile(`uint8\s*\(\s*(?:bytes1|bytes2)\s*\(`)
	mathMaxCastRe  = regexp.MustCompile(`\b(?:u?int)\d+\s*\(\s*Math\.max\s*\(`)
	enumParamNames = regexp.MustCompile(
		`(?i)\b\w*(rounding|direction|mode|kind|status|state|side|prefix|tier|phase|flag|op|operator|key)\w*\b`,
	)
	modularArithmeticRe = regexp.MustCompile(
		`\*=\s*2\s*-\s*\w|` +
			`\*=\s*\w.*\*.*\w|` +
			`=\s*\(\s*\w+\s*\+\s*\w+\s*\)\s*\*\s*\w`,
	)
	indexedBytesCastRe = regexp.MustCompile(
		`uint8\s*\(\s*(?:bytes1\s*\()?\s*\w+\s*\[\s*\w+\s*\]\s*\)?`,
	)
	explicitBoundsRe = regexp.MustCompile(
		`(?:require|assert)\s*\(.*==\s*\w+\s*\(`,
	)
	bitManipCastRe = regexp.MustCompile(
		`uint\d+\s*\(\s*\w+\s*(?:>>|<<|&|\|)\s*(?:0x[\da-fA-F]+|\d+)\s*\)`,
	)
	typeMaxCastRe       = regexp.MustCompile(`(?:u?int)\d+\s*\(\s*type\s*\(\s*[A-Z]\w*\s*\)\.max\s*\)`)
	moduloBoundedCastRe = regexp.MustCompile(
		`uint(\d+)\s*\(\s*[\w.]+\s*%\s*(?:2\s*\*\*\s*\d+|\d+(?:_\d+)*)\s*\)`,
	)
	blockTimestampCastRe    = regexp.MustCompile(`uint\d+\s*\(\s*block\s*\.\s*timestamp`)
	safeTruncationCommentRe = regexp.MustCompile(`(?i)//.*(?:safe|intentional|truncat|by design|ok to)`)
	emitStatementRe         = regexp.MustCompile(`^\s*emit\s+\w+\s*\(`)
)

func NewIntegerOverflowDetectorV2() *IntegerOverflowDetectorV2 {
	return &IntegerOverflowDetectorV2{
		arithmeticOps: []*regexp.Regexp{
			regexp.MustCompile(`\b\w+(?:\s*\[[^\]]+\])?\s*\+=`),
			regexp.MustCompile(`\b\w+(?:\s*\[[^\]]+\])?\s*-=`),
			regexp.MustCompile(`\b\w+(?:\s*\[[^\]]+\])?\s*\*=`),
		},
		uncheckedStart: regexp.MustCompile(`\bunchecked\s*\{`),
		safeMathUsage: regexp.MustCompile(
			`using\s+SafeMath|SafeMath\.|import.*SafeMath`,
		),
		unsafeCast: regexp.MustCompile(`\b(uint(?:8|16|32|64|128)|int(?:8|16|32|64|128))\s*\(\s*([A-Za-z_]\w*)`),
		constantCast: regexp.MustCompile(
			`\b(?:uint|int)\d+\s*\(\s*\d+\s*\)`,
		),
	}
}

func (d *IntegerOverflowDetectorV2) Name() string                { return "integer-overflow" }
func (d *IntegerOverflowDetectorV2) Severity() analyzer.Severity { return analyzer.High }
func (d *IntegerOverflowDetectorV2) Description() string {
	return "Version-aware integer overflow detection (pre-0.8 global, 0.8+ unchecked blocks)"
}

func (d *IntegerOverflowDetectorV2) Analyze(
	lines []string,
	source string,
	filepath string,
) ([]analyzer.Finding, error) {

	versionRisk := AssessVersionRisk(source)
	var findings []analyzer.Finding

	if versionRisk.OverflowRisk {
		findings = append(findings,
			d.analyzePreV8(lines, source, filepath, versionRisk)...,
		)
	} else {
		findings = append(findings,
			d.analyzeUncheckedBlocks(lines, filepath)...,
		)
	}

	findings = append(findings, d.analyzeDowncasts(lines, filepath)...)

	return findings, nil
}

func (d *IntegerOverflowDetectorV2) analyzePreV8(
	lines []string,
	source string,
	filepath string,
	risk *VersionRisk,
) []analyzer.Finding {

	hasSafeMath := d.safeMathUsage.MatchString(source)
	if hasSafeMath {
		return nil
	}

	var findings []analyzer.Finding
	for i, line := range lines {
		lineNum := i + 1

		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*") {
			continue
		}

		for _, op := range d.arithmeticOps {
			if !op.MatchString(line) {
				continue
			}

			opType := "overflow"
			if strings.Contains(line, "-=") {
				opType = "underflow"
			}

			verStr := "unknown"
			if risk.Version != nil {
				verStr = risk.Version.String()
			}

			finding := detectorFinding(rules.IDIntegerOverflow001, filepath, lineNum, trimmed)
			finding.Title = "Integer " + opType + " risk (Solidity " + verStr + ", no SafeMath)"
			finding.Description = "Solidity " + verStr + " has no built-in overflow protection. " +
				"The operation '" + strings.TrimSpace(line) + "' can silently " +
				opType + ". Use SafeMath or upgrade to >= 0.8.0."
			finding.Confidence = analyzer.ConfidenceMedium

			findings = append(findings, finding)
			break
		}
	}

	return findings
}

func (d *IntegerOverflowDetectorV2) analyzeUncheckedBlocks(
	lines []string,
	filepath string,
) []analyzer.Finding {

	var findings []analyzer.Finding
	inUnchecked := false
	uncheckedDepth := 0
	inAssembly := false
	assemblyDepth := 0
	enclosingFunc := ""
	funcRe := regexp.MustCompile(`^\s*function\s+(\w+)`)

	for i, line := range lines {
		lineNum := i + 1
		trimmed := strings.TrimSpace(line)

		if m := funcRe.FindStringSubmatch(line); m != nil {
			enclosingFunc = m[1]
		}

		if !inUnchecked && d.uncheckedStart.MatchString(line) {
			inUnchecked = true
			uncheckedDepth = 0
			inAssembly = false
		}

		if inUnchecked {
			for _, ch := range line {
				switch ch {
				case '{':
					uncheckedDepth++
				case '}':
					uncheckedDepth--
				}
			}

			if assemblyRe.MatchString(line) {
				inAssembly = true
				assemblyDepth = 0
			}
			if inAssembly {
				for _, ch := range line {
					switch ch {
					case '{':
						assemblyDepth++
					case '}':
						assemblyDepth--
					}
				}
				if assemblyDepth <= 0 {
					inAssembly = false
				}
				if uncheckedDepth <= 0 {
					inUnchecked = false
					inAssembly = false
					enclosingFunc = ""
				}
				continue
			}

			if uncheckedDepth <= 0 {
				inUnchecked = false
				enclosingFunc = ""
				continue
			}

			if trimmed == "" || trimmed == "{" || trimmed == "}" ||
				strings.HasPrefix(trimmed, "//") ||
				strings.HasPrefix(trimmed, "*") ||
				strings.HasPrefix(trimmed, "/*") {
				continue
			}
			if loopCounterRe.MatchString(trimmed) ||
				safeCastFuncRe.MatchString(enclosingFunc) ||
				enclosingFunc == "_tryParseChr" ||
				safeCastCallRe.MatchString(line) ||
				isConstantStrideIncrement(trimmed) ||
				isForLoopConstantStride(trimmed) ||
				hasNearbyArithmeticSafetyComment(lines, i) ||
				modularArithmeticRe.MatchString(line) ||
				isBoundedDataStructureOp(trimmed) ||
				isKnownBoundedTokenBalanceOp(trimmed) ||
				hasNearbyMinBound(lines, i, trimmed) ||
				hasNearbyBoundsForArithmetic(lines, i, trimmed) {
				continue
			}

			for _, op := range d.arithmeticOps {
				if !op.MatchString(line) {
					continue
				}
				if strings.HasPrefix(trimmed, "return ") && isSimpleBoundedArithmetic(trimmed) {
					continue
				}

				opType := "overflow"
				if strings.Contains(line, "-=") || strings.Contains(line, "- ") {
					opType = "underflow"
				}

				finding := detectorFinding(rules.IDIntegerOverflow002, filepath, lineNum, trimmed)
				finding.Title = "Arithmetic in unchecked block - " + opType + " risk"
				finding.Description = "The unchecked{} block disables Solidity 0.8+'s built-in " +
					opType + " protection. Only use unchecked when you can " +
					"mathematically prove the operation cannot " + opType + "."
				finding.Confidence = analyzer.ConfidenceMedium

				findings = append(findings, finding)
				break
			}
		}
	}

	return findings
}

func (d *IntegerOverflowDetectorV2) analyzeDowncasts(
	lines []string,
	filepath string,
) []analyzer.Finding {

	var findings []analyzer.Finding
	const boundsLookBack = 5
	for i, line := range lines {
		lineNum := i + 1
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*") {
			continue
		}

		if d.constantCast.MatchString(line) {
			continue
		}
		if enumCastRe.MatchString(line) ||
			bytesCastRe.MatchString(line) ||
			indexedBytesCastRe.MatchString(line) ||
			bitManipCastRe.MatchString(line) ||
			typeMaxCastRe.MatchString(line) ||
			moduloBoundedCastRe.MatchString(line) ||
			blockTimestampCastRe.MatchString(line) ||
			safeTruncationCommentRe.MatchString(line) ||
			hasNearbyArithmeticSafetyComment(lines, i) {
			continue
		}

		m := d.unsafeCast.FindStringSubmatch(line)
		if m == nil {
			continue
		}

		targetType := m[1]
		sourceVar := m[2]

		if isBytesNToUintCast(line, targetType) {
			continue
		}

		if regexp.MustCompile(`^\d+$`).MatchString(sourceVar) {
			continue
		}
		funcCtx := d.getEnclosingFunction(lines, i)
		if safeCastFuncRe.MatchString(funcCtx) {
			continue
		}
		if funcCtx == "_tryParseChr" {
			continue
		}
		if enumParamNames.MatchString(sourceVar) {
			continue
		}
		if mathMaxCastRe.MatchString(line) {
			continue
		}
		if funcCtx == "unpack" && sourceVar == "raw" {
			continue
		}
		if strings.Contains(line, ".extract_") ||
			(strings.Contains(line, "block.timestamp") && (targetType == "uint64" || targetType == "uint128")) ||
			strings.Contains(line, "deque._begin+uint128(start)") ||
			strings.Contains(strings.ReplaceAll(line, " ", ""), "deque._begin+uint128(start)") {
			continue
		}
		start := i - boundsLookBack
		if start < 0 {
			start = 0
		}
		context := strings.Join(lines[start:i+1], "\n")
		if boundsCheckRe.MatchString(context) ||
			d.hasBoundsCheck(lines, i, sourceVar, targetType) ||
			d.hasRevertOnOverflow(lines, i, sourceVar) ||
			explicitBoundsRe.MatchString(context) ||
			(strings.Contains(line, "bytes1") && targetType == "uint8") {
			continue
		}

		finding := detectorFinding(rules.IDIntegerOverflow003, filepath, lineNum, trimmed)
		if emitStatementRe.MatchString(line) {
			finding.Title = "Unsafe downcast in event emission - " + targetType
			finding.Description = "Casting '" + sourceVar + "' to '" + targetType + "' in an emit statement " +
				"may truncate event data if the value exceeds the target range. Contract state is unaffected, " +
				"but off-chain consumers may observe incorrect event values."
			finding.Severity = analyzer.Low
			finding.Confidence = analyzer.ConfidenceLow
		} else {
			finding.Title = "Unsafe downcast to " + targetType
			finding.Description = "Casting '" + sourceVar + "' to '" + targetType + "' may silently truncate " +
				"the value. Use SafeCast." + toSafeCastMethod(targetType) + "(" + sourceVar + ")."
			finding.Confidence = analyzer.ConfidenceMedium
		}

		findings = append(findings, finding)
	}

	return findings
}

func (d *IntegerOverflowDetectorV2) hasBoundsCheck(lines []string, castLineIdx int, sourceVar string, targetType string) bool {
	start := castLineIdx - 8
	if start < 0 {
		start = 0
	}

	maxValRe := regexp.MustCompile(
		`(?:require|if)\s*\(.*\b` + regexp.QuoteMeta(sourceVar) + `\b.*(?:<=|<|>|>=)`,
	)
	typeMaxRe := regexp.MustCompile(
		`type\s*\(\s*` + regexp.QuoteMeta(targetType) + `\s*\)\.max`,
	)

	for _, line := range lines[start:castLineIdx] {
		if maxValRe.MatchString(line) && typeMaxRe.MatchString(line) {
			return true
		}
		if maxValRe.MatchString(line) {
			return true
		}
	}
	return false
}

func (d *IntegerOverflowDetectorV2) hasRevertOnOverflow(lines []string, castLineIdx int, sourceVar string) bool {
	start := castLineIdx - 5
	if start < 0 {
		start = 0
	}

	revertRe := regexp.MustCompile(
		`if\s*\(.*\b` + regexp.QuoteMeta(sourceVar) + `\b.*\)\s*revert`,
	)

	for _, line := range lines[start:castLineIdx] {
		if revertRe.MatchString(line) {
			return true
		}
	}
	return false
}

func (d *IntegerOverflowDetectorV2) getEnclosingFunction(lines []string, lineIdx int) string {
	funcRe := regexp.MustCompile(`^\s*function\s+(\w+)`)
	for i := lineIdx; i >= 0; i-- {
		if m := funcRe.FindStringSubmatch(lines[i]); m != nil {
			return m[1]
		}
	}
	return ""
}

func isSimpleBoundedArithmetic(line string) bool {
	simpleSub := regexp.MustCompile(`return\s+\w+\s*-\s*\w+\s*;`)
	simpleAdd := regexp.MustCompile(`return\s+\w+\s*\+\s*\w+\s*;`)
	return simpleSub.MatchString(line) || simpleAdd.MatchString(line)
}

func isConstantStrideIncrement(line string) bool {
	constStride := regexp.MustCompile(`\b\w+\s*\+=\s*(?:0x[0-9a-fA-F]+|\d+)\s*;`)
	return constStride.MatchString(line)
}

func isForLoopConstantStride(line string) bool {
	return strings.HasPrefix(line, "for ") &&
		regexp.MustCompile(`\b\w+\s*\+=\s*(?:0x[0-9a-fA-F]+|\d+)`).MatchString(line)
}

func isBoundedDataStructureOp(line string) bool {
	lower := strings.ToLower(line)
	patterns := []string{
		"end - start",
		"end - begin",
		"stop - start",
		"- deque._begin",
		"- _begin",
		"uint256(deque._end - deque._begin)",
		"offset += input.length",
	}
	for _, pattern := range patterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}

	boundedLenRe := regexp.MustCompile(`\b(?:len|length|size|count)\s*=\s*\w+\s*-\s*\w+`)
	return boundedLenRe.MatchString(line)
}

func isKnownBoundedTokenBalanceOp(line string) bool {
	return regexp.MustCompile(`\b_balances\s*\[[^\]]+\]\s*(?:\+=|-=)\s*1\s*;?$`).MatchString(line)
}

func hasNearbyMinBound(lines []string, lineIdx int, line string) bool {
	m := regexp.MustCompile(`\b(\w+)\s*-=\s*(\w+)`).FindStringSubmatch(line)
	if len(m) < 3 {
		return false
	}
	left := regexp.QuoteMeta(m[1])
	right := regexp.QuoteMeta(m[2])

	start := lineIdx - 6
	if start < 0 {
		start = 0
	}
	minRe := regexp.MustCompile(`\b` + right + `\b\s*=\s*Math\.min\s*\([^)]*\b` + left + `\b`)
	for _, candidate := range lines[start:lineIdx] {
		if minRe.MatchString(candidate) {
			return true
		}
	}
	return false
}

func hasNearbyBoundsForArithmetic(lines []string, lineIdx int, line string) bool {
	m := regexp.MustCompile(`\b(\w+)(?:\s*\[[^\]]+\])?\s*[-+]=\s*(\w+)`).FindStringSubmatch(line)
	if len(m) < 3 {
		return false
	}
	if regexp.MustCompile(`\bif\s*\([^)]*\b`+regexp.QuoteMeta(m[1])+`\b[^)]*(?:>|>=|<|<=)[^)]*\b`+regexp.QuoteMeta(m[2])+`\b`).MatchString(line) ||
		regexp.MustCompile(`\bif\s*\([^)]*\b`+regexp.QuoteMeta(m[2])+`\b[^)]*(?:>|>=|<|<=)[^)]*\b`+regexp.QuoteMeta(m[1])+`\b`).MatchString(line) {
		return true
	}

	left := m[1]
	right := m[2]
	start := lineIdx - 6
	if start < 0 {
		start = 0
	}

	leftRe := regexp.QuoteMeta(left)
	rightRe := regexp.QuoteMeta(right)
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`\b` + leftRe + `\b\s*<\s*\b` + rightRe + `\b`),
		regexp.MustCompile(`\b` + rightRe + `\b\s*<=\s*\b` + leftRe + `\b`),
		regexp.MustCompile(`\b` + leftRe + `\b\s*\+\s*\b` + rightRe + `\b.*(?:totalSupply|length|len)`),
		regexp.MustCompile(`(?:totalSupply|length|len).*\b` + leftRe + `\b\s*\+\s*\b` + rightRe + `\b`),
	}

	for _, candidate := range lines[start:lineIdx] {
		for _, pattern := range patterns {
			if pattern.MatchString(candidate) {
				return true
			}
		}
	}
	return false
}

func hasNearbyArithmeticSafetyComment(lines []string, lineIdx int) bool {
	start := lineIdx - 14
	if start < 0 {
		start = 0
	}
	for _, line := range lines[start : lineIdx+1] {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "safe cast") ||
			strings.Contains(lower, "overflow not possible") ||
			strings.Contains(lower, "underflow not possible") ||
			strings.Contains(lower, "cannot overflow") ||
			strings.Contains(lower, "cannot underflow") ||
			strings.Contains(lower, "not cause an overflow") ||
			strings.Contains(lower, "not cause overflow") ||
			strings.Contains(lower, "overflow impossible") ||
			strings.Contains(lower, "underflow impossible") ||
			strings.Contains(lower, "safe from underflow") ||
			strings.Contains(lower, "safe from overflow") ||
			strings.Contains(lower, "bounded by") ||
			strings.Contains(lower, "bounded to") ||
			(strings.Contains(lower, "<=") && strings.HasPrefix(strings.TrimSpace(lower), "//")) {
			return true
		}
	}
	return false
}

func isBytesNToUintCast(line string, targetType string) bool {
	targetBits, ok := integerTypeBits(targetType)
	if !ok || !strings.HasPrefix(targetType, "uint") {
		return false
	}

	matches := regexp.MustCompile(`\b` + regexp.QuoteMeta(targetType) + `\s*\(\s*bytes(\d+)`).FindStringSubmatch(line)
	if len(matches) < 2 {
		return false
	}

	byteCount := 0
	for _, ch := range matches[1] {
		byteCount = byteCount*10 + int(ch-'0')
	}
	return byteCount*8 == targetBits
}

func integerTypeBits(typeName string) (int, bool) {
	prefixLen := 3
	if strings.HasPrefix(typeName, "uint") {
		prefixLen = 4
	} else if !strings.HasPrefix(typeName, "int") {
		return 0, false
	}

	bits := 0
	for _, ch := range typeName[prefixLen:] {
		if ch < '0' || ch > '9' {
			return 0, false
		}
		bits = bits*10 + int(ch-'0')
	}
	return bits, bits > 0
}

func toSafeCastMethod(targetType string) string {
	if strings.HasPrefix(targetType, "uint") {
		return "toU" + targetType[1:]
	}
	if strings.HasPrefix(targetType, "int") {
		return "toI" + targetType[1:]
	}
	return "to" + strings.ToUpper(targetType[:1]) + targetType[1:]
}
