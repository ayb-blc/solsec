package reporter

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/ayb-blc/solsec/internal/analyzer"
)

const (
	colorReset   = "\033[0m"
	colorBold    = "\033[1m"
	colorDim     = "\033[2m"
	colorRed     = "\033[31m"
	colorYellow  = "\033[33m"
	colorBlue    = "\033[34m"
	colorMagenta = "\033[35m"
	colorCyan    = "\033[36m"
	colorWhite   = "\033[37m"
	colorGreen   = "\033[32m"

	// Severity renkleri
	colorCritical = "\033[35m"
	colorHigh     = "\033[31m" // Red
	colorMedium   = "\033[33m" // Yellow
	colorLow      = "\033[36m" // Cyan
	colorInfo     = "\033[37m" // White

	boxTop    = "╔══════════════════════════════════════════════════════════╗"
	boxBottom = "╚══════════════════════════════════════════════════════════╝"
	boxSide   = "║"
	divider   = "──────────────────────────────────────────────────────────"
)

type TextReporter struct {
	out      io.Writer
	useColor bool
	verbose  bool
}

// Optional flags: useColor, verbose. Defaults: useColor=true, verbose=false.
func NewText(out io.Writer, options ...bool) *TextReporter {
	useColor := true
	verbose := false
	if len(options) > 0 {
		useColor = options[0]
	}
	if len(options) > 1 {
		verbose = options[1]
	}
	return &TextReporter{
		out:      out,
		useColor: useColor,
		verbose:  verbose,
	}
}

func (r *TextReporter) Report(results []analyzer.AnalysisResult) error {
	stats := ComputeStats(results)

	r.printHeader(stats)

	r.printAnalysisErrors(results)

	if stats.TotalFindings == 0 {
		if !HasAnalysisErrors(results) {
			r.printSuccess()
		}
		return nil
	}

	grouped := groupBySeverity(results)

	for _, sev := range []analyzer.Severity{
		analyzer.Critical,
		analyzer.High,
		analyzer.Medium,
		analyzer.Low,
		analyzer.Info,
	} {
		findings, ok := grouped[sev]
		if !ok || len(findings) == 0 {
			continue
		}
		r.printSeverityGroup(sev, findings)
	}

	r.printSummary(stats)

	return nil
}

func (r *TextReporter) printHeader(stats SummaryStats) {
	r.printf("\n")
	r.printf("%s%s solsec — Solidity Security Analyzer %s\n",
		colorBold, colorCyan, colorReset)
	r.printf("%s%s files analyzed%s\n\n",
		colorDim,
		fmt.Sprintf("%d", stats.TotalFiles),
		colorReset,
	)
}

func (r *TextReporter) printSuccess() {
	r.printf("%s✓ No vulnerabilities detected%s\n\n", colorGreen, colorReset)
}

func (r *TextReporter) printSeverityGroup(sev analyzer.Severity, findings []findingWithFile) {
	sevColor := r.severityColor(sev)
	sevIcon := severityIcon(sev)

	r.printf("\n%s%s %s %s (%d)%s\n",
		colorBold, sevColor, sevIcon, sev.String(), len(findings), colorReset)
	r.printf("%s%s%s\n", colorDim, divider, colorReset)

	for i, fw := range findings {
		r.printFinding(i+1, fw)
	}
}

// Format:
//
//	[1] Potential reentrancy in function 'withdraw'
//	    contracts/Vault.sol:42
//	    (bool success,) = msg.sender.call{value: amount}("");
//	    Confidence: HIGH
func (r *TextReporter) printFinding(num int, fw findingWithFile) {
	f := fw.finding

	r.printf("\n  %s[%d]%s %s%s%s\n",
		colorBold, num, colorReset,
		colorBold, f.Title, colorReset,
	)

	// Lokasyon
	if f.Filepath != "" {
		r.printf("      %s%s%s",
			colorDim,
			formatLocation(f.Filepath, f.Line),
			colorReset,
		)
		r.printf("  %s[%s]%s\n",
			colorDim, f.DetectorName, colorReset,
		)
	}

	if f.CodeSnippet != "" {
		r.printf("\n")
		for _, line := range strings.Split(f.CodeSnippet, "\n") {
			r.printf("      %s│%s %s\n", colorDim, colorReset, line)
		}
		r.printf("\n")
	}

	if f.Description != "" {
		r.printf("      %sℹ%s %s\n",
			colorBlue, colorReset,
			wrapText(f.Description, 70, "        "),
		)
	}

	if r.verbose && f.Recommendation != "" {
		r.printf("\n      %s✎%s %s\n",
			colorGreen, colorReset,
			wrapText(f.Recommendation, 70, "        "),
		)
	}

	if len(f.Tags) > 0 {
		r.printf("\n      %s🏷  %s%s\n",
			colorDim,
			strings.Join(f.Tags, ", "),
			colorReset,
		)
	}

	r.printf("      %sConfidence: %s%s\n",
		colorDim, f.Confidence.String(), colorReset,
	)
}

func (r *TextReporter) printSummary(stats SummaryStats) {
	r.printf("\n%s%s Summary %s\n", colorBold, colorWhite, colorReset)
	r.printf("%s%s%s\n", colorDim, divider, colorReset)

	r.printf("  Files analyzed:    %s%d%s\n",
		colorBold, stats.TotalFiles, colorReset)
	r.printf("  Files with issues: %s%d%s\n",
		colorBold, stats.FilesWithBugs, colorReset)
	r.printf("  Total findings:    %s%d%s\n\n",
		colorBold, stats.TotalFindings, colorReset)

	maxCount := 0
	for _, count := range stats.BySeverity {
		if count > maxCount {
			maxCount = count
		}
	}

	for _, sev := range []analyzer.Severity{
		analyzer.Critical, analyzer.High, analyzer.Medium, analyzer.Low, analyzer.Info,
	} {
		count := stats.BySeverity[sev]
		if count == 0 {
			continue
		}

		sevColor := r.severityColor(sev)
		barLen := 0
		if maxCount > 0 {
			barLen = (count * 20) / maxCount // Max 20 karakter
		}
		if barLen == 0 {
			barLen = 1
		}
		bar := strings.Repeat("█", barLen)

		r.printf("  %s%-10s%s %s%-20s%s %s%d%s\n",
			sevColor+colorBold, sev.String(), colorReset,
			sevColor, bar, colorReset,
			colorBold, count, colorReset,
		)
	}

	if len(stats.ByDetector) > 1 {
		r.printf("\n%s%s By Detector %s\n", colorDim, colorWhite, colorReset)
		detectors := make([]string, 0, len(stats.ByDetector))
		for d := range stats.ByDetector {
			detectors = append(detectors, d)
		}
		sort.Strings(detectors)

		for _, det := range detectors {
			r.printf("  %-30s %s%d%s\n",
				det, colorBold, stats.ByDetector[det], colorReset)
		}
	}

	r.printf("\n")
}

func (r *TextReporter) printAnalysisErrors(results []analyzer.AnalysisResult) {
	var failed []analyzer.AnalysisResult
	for _, result := range results {
		if result.Error != nil {
			failed = append(failed, result)
		}
	}
	if len(failed) == 0 {
		return
	}

	r.printf("%s%s Analysis errors (%d)%s\n", colorBold, colorRed, len(failed), colorReset)
	r.printf("%s%s%s\n", colorDim, divider, colorReset)
	for _, result := range failed {
		r.printf("  %s%s%s: %s\n", colorDim, result.Filepath, colorReset, result.Error)
	}
	r.printf("\n")
}

func (r *TextReporter) printf(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	if !r.useColor {
		msg = stripANSI(msg)
	}
	fmt.Fprint(r.out, msg)
}

func (r *TextReporter) severityColor(sev analyzer.Severity) string {
	if !r.useColor {
		return ""
	}
	switch sev {
	case analyzer.Critical:
		return colorCritical
	case analyzer.High:
		return colorHigh
	case analyzer.Medium:
		return colorMedium
	case analyzer.Low:
		return colorLow
	default:
		return colorInfo
	}
}

func severityIcon(sev analyzer.Severity) string {
	switch sev {
	case analyzer.Critical:
		return "🔴"
	case analyzer.High:
		return "🟠"
	case analyzer.Medium:
		return "🟡"
	case analyzer.Low:
		return "🔵"
	default:
		return "⚪"
	}
}

type findingWithFile struct {
	finding  analyzer.Finding
	filepath string
}

func groupBySeverity(results []analyzer.AnalysisResult) map[analyzer.Severity][]findingWithFile {
	grouped := make(map[analyzer.Severity][]findingWithFile)

	for _, result := range results {
		for _, f := range result.Findings {
			grouped[f.Severity] = append(grouped[f.Severity], findingWithFile{
				finding:  f,
				filepath: result.Filepath,
			})
		}
	}

	for sev := range grouped {
		sort.Slice(grouped[sev], func(i, j int) bool {
			fi, fj := grouped[sev][i], grouped[sev][j]
			if fi.filepath != fj.filepath {
				return fi.filepath < fj.filepath
			}
			return fi.finding.Line < fj.finding.Line
		})
	}

	return grouped
}

func formatLocation(filepath string, line int) string {
	const maxLen = 40
	if len(filepath) > maxLen {
		filepath = "..." + filepath[len(filepath)-maxLen:]
	}
	if line > 0 {
		return fmt.Sprintf("%s:%d", filepath, line)
	}
	return filepath
}

func wrapText(text string, width int, indent string) string {
	if len(text) <= width {
		return text
	}

	var lines []string
	words := strings.Fields(text)
	currentLine := ""

	for _, word := range words {
		if len(currentLine)+len(word)+1 > width && currentLine != "" {
			lines = append(lines, currentLine)
			currentLine = word
		} else {
			if currentLine == "" {
				currentLine = word
			} else {
				currentLine += " " + word
			}
		}
	}
	if currentLine != "" {
		lines = append(lines, currentLine)
	}

	return strings.Join(lines, "\n"+indent)
}

func stripANSI(s string) string {
	var result strings.Builder
	inEscape := false
	for _, ch := range s {
		if ch == '\033' {
			inEscape = true
			continue
		}
		if inEscape {
			if ch == 'm' {
				inEscape = false
			}
			continue
		}
		result.WriteRune(ch)
	}
	return result.String()
}
