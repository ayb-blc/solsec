package detectors

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/ayb-blc/solsec/internal/analyzer"
)

type IntegerOverflowDetector struct {
	// Pragma version pattern'i
	pragmaPattern *regexp.Regexp

	uncheckedPattern *regexp.Regexp

	// Tehlikeli aritmetik operasyonlar
	arithmeticPatterns []*regexp.Regexp

	safeMathPatterns []*regexp.Regexp

	unsafeCastPatterns []*regexp.Regexp
}

func NewIntegerOverflowDetector() *IntegerOverflowDetector {
	return &IntegerOverflowDetector{
		pragmaPattern: regexp.MustCompile(
			`pragma\s+solidity\s+[\^~>=<]*\s*(\d+)\.(\d+)`,
		),

		uncheckedPattern: regexp.MustCompile(`\bunchecked\s*\{`),

		arithmeticPatterns: buildArithmeticPatterns(),

		safeMathPatterns: []*regexp.Regexp{
			regexp.MustCompile(`using\s+SafeMath\s+for`),
			regexp.MustCompile(`SafeMath\.`),
			regexp.MustCompile(`import.*SafeMath`),
		},

		unsafeCastPatterns: []*regexp.Regexp{
			regexp.MustCompile(`uint8\s*\(\s*\w+`),
			regexp.MustCompile(`uint16\s*\(\s*\w+`),
			regexp.MustCompile(`uint32\s*\(\s*\w+`),
			regexp.MustCompile(`int8\s*\(\s*\w+`),
		},
	}
}

func (d *IntegerOverflowDetector) Name() string                { return "integer-overflow" }
func (d *IntegerOverflowDetector) Severity() analyzer.Severity { return analyzer.High }
func (d *IntegerOverflowDetector) Description() string {
	return "Detects integer overflow/underflow risks in arithmetic operations"
}

func (d *IntegerOverflowDetector) Analyze(
	lines []string,
	source string,
	filepath string,
) ([]analyzer.Finding, error) {
	var findings []analyzer.Finding

	version := d.detectSolidityVersion(source)

	if version.major == 0 && version.minor < 8 {
		findings = append(findings,
			d.checkOldSolidity(lines, source, filepath, version)...,
		)
	} else {
		findings = append(findings,
			d.checkUncheckedBlocks(lines, source, filepath)...,
		)
	}

	// Her iki versiyonda da: unsafe type cast
	findings = append(findings,
		d.checkUnsafeCasts(lines, filepath)...,
	)

	return findings, nil
}

type solidityVersion struct{ major, minor, patch int }

func (d *IntegerOverflowDetector) detectSolidityVersion(source string) solidityVersion {
	matches := d.pragmaPattern.FindStringSubmatch(source)
	if len(matches) < 3 {
		return solidityVersion{0, 8, 0}
	}

	var v solidityVersion
	fmt.Sscanf(matches[1], "%d", &v.major)
	fmt.Sscanf(matches[2], "%d", &v.minor)
	return v
}

func (d *IntegerOverflowDetector) checkOldSolidity(
	lines []string,
	source string,
	filepath string,
	version solidityVersion,
) []analyzer.Finding {
	var findings []analyzer.Finding

	usesSafeMath := false
	for _, pattern := range d.safeMathPatterns {
		if pattern.MatchString(source) {
			usesSafeMath = true
			break
		}
	}

	if usesSafeMath {
		return nil
	}

	dangerousOps := buildArithmeticPatterns()

	for i, line := range lines {
		lineNum := i + 1

		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*") {
			continue
		}

		for _, op := range dangerousOps {
			if !op.MatchString(line) {
				continue
			}

			opType := "overflow"
			if strings.Contains(line, "-=") {
				opType = "underflow"
			}

			findings = append(findings, analyzer.Finding{
				DetectorName: d.Name(),
				Title: fmt.Sprintf(
					"Potential integer %s (Solidity %d.%d, no SafeMath)",
					opType, version.major, version.minor,
				),
				Description: fmt.Sprintf(
					"Solidity %d.%d does not have built-in overflow protection. "+
						"The operation '%s' can silently %s without SafeMath. "+
						"This can lead to unexpected behavior and fund loss.",
					version.major, version.minor,
					strings.TrimSpace(line), opType,
				),
				Recommendation: "Use SafeMath library or upgrade to Solidity >= 0.8.0:\n" +
					"  import '@openzeppelin/contracts/utils/math/SafeMath.sol';\n" +
					"  using SafeMath for uint256;\n" +
					"  // Then use: balance = balance.add(amount);",
				Filepath:    filepath,
				Line:        lineNum,
				CodeSnippet: strings.TrimSpace(line),
				Severity:    analyzer.High,
				Confidence:  analyzer.ConfidenceMedium,
				Tags:        []string{"integer-overflow", opType, "no-safemath"},
			})
			break
		}
	}

	return findings
}

func (d *IntegerOverflowDetector) checkUncheckedBlocks(
	lines []string,
	_ string,
	filepath string,
) []analyzer.Finding {
	var findings []analyzer.Finding

	inUnchecked := false
	uncheckedDepth := 0
	uncheckedStart := 0
	reportedInBlock := false

	for i, line := range lines {
		lineNum := i + 1

		if d.uncheckedPattern.MatchString(line) {
			inUnchecked = true
			uncheckedDepth = 0
			uncheckedStart = lineNum
			reportedInBlock = false
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

			if uncheckedDepth <= 0 && uncheckedStart > 0 {
				// unchecked blok bitti
				inUnchecked = false
				continue
			}
			if reportedInBlock {
				continue
			}

			trimmed := strings.TrimSpace(stripInlineComment(line))
			if strings.HasPrefix(trimmed, "//") {
				continue
			}

			for _, pattern := range d.arithmeticPatterns {
				if pattern.MatchString(trimmed) {
					findings = append(findings, analyzer.Finding{
						DetectorName: d.Name(),
						Title: fmt.Sprintf(
							"Arithmetic in unchecked block at line %d", lineNum,
						),
						Description: "Arithmetic operation inside 'unchecked' block bypasses " +
							"Solidity 0.8+ overflow protection. " +
							"Ensure this operation cannot overflow/underflow, " +
							"especially if values are user-controlled.",
						Recommendation: "Only use 'unchecked' when you can mathematically prove " +
							"that overflow/underflow is impossible:\n" +
							"  // Safe: loop counter bounded by array length\n" +
							"  unchecked { i++; }  // i < array.length guaranteed\n\n" +
							"  // Dangerous: user-supplied value\n" +
							"  unchecked { balance -= amount; }  // amount could exceed balance",
						Filepath:    filepath,
						Line:        lineNum,
						CodeSnippet: trimmed,
						Severity:    analyzer.Medium,
						Confidence:  analyzer.ConfidenceMedium,
						Tags:        []string{"integer-overflow", "unchecked", "arithmetic"},
					})
					reportedInBlock = true
					break
				}
			}
		}
	}

	return findings
}

func buildArithmeticPatterns() []*regexp.Regexp {
	operand := `[A-Za-z_]\w*(?:\s*\[[^\]]+\]|\s*\.\s*[A-Za-z_]\w*)*`
	return []*regexp.Regexp{
		regexp.MustCompile(operand + `\s*\+=\s*`),
		regexp.MustCompile(operand + `\s*-=\s*`),
		regexp.MustCompile(operand + `\s*\*=\s*`),
		regexp.MustCompile(operand + `\s*\+\s*` + operand),
		regexp.MustCompile(operand + `\s*-\s*` + operand),
		regexp.MustCompile(operand + `\s*\*\s*` + operand),
	}
}

func stripInlineComment(line string) string {
	if idx := strings.Index(line, "//"); idx >= 0 {
		return line[:idx]
	}
	return line
}

func (d *IntegerOverflowDetector) checkUnsafeCasts(
	lines []string,
	filepath string,
) []analyzer.Finding {
	var findings []analyzer.Finding

	for i, line := range lines {
		lineNum := i + 1
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "//") {
			continue
		}

		for _, pattern := range d.unsafeCastPatterns {
			if !pattern.MatchString(line) {
				continue
			}

			if regexp.MustCompile(`uint\d+\s*\(\s*\d+\s*\)`).MatchString(line) {
				continue
			}

			findings = append(findings, analyzer.Finding{
				DetectorName: d.Name(),
				Title:        fmt.Sprintf("Unsafe integer downcast at line %d", lineNum),
				Description: "Downcasting to a smaller integer type can silently truncate values. " +
					"For example, uint256 value 256 cast to uint8 becomes 0.",
				Recommendation: "Use OpenZeppelin's SafeCast library:\n" +
					"  import '@openzeppelin/contracts/utils/math/SafeCast.sol';\n" +
					"  uint8 safe = SafeCast.toUint8(largeValue); // reverts on overflow",
				Filepath:    filepath,
				Line:        lineNum,
				CodeSnippet: trimmed,
				Severity:    analyzer.Medium,
				Confidence:  analyzer.ConfidenceMedium,
				Tags:        []string{"integer-overflow", "unsafe-cast", "truncation"},
			})
			break
		}
	}

	return findings
}
