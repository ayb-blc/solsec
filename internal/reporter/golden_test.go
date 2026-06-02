package reporter_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ayb-blc/solsec/internal/analyzer"
	"github.com/ayb-blc/solsec/internal/reporter"
)

func TestTextReporterGolden_NoFindings(t *testing.T) {
	results := []analyzer.AnalysisResult{{Filepath: "contracts/Safe.sol"}}
	assertGolden(t, "text_no_findings.txt", renderText(t, results))
}

func TestTextReporterGolden_WithFindings(t *testing.T) {
	results := []analyzer.AnalysisResult{
		{
			Filepath: "contracts/Vault.sol",
			Findings: []analyzer.Finding{
				{
					DetectorName:   "reentrancy",
					Title:          "Potential reentrancy in function 'withdraw'",
					Description:    "External interaction happens before a later state update.",
					Recommendation: "Move state updates before external calls.",
					Filepath:       "contracts/Vault.sol",
					Line:           12,
					CodeSnippet:    `(bool ok,) = msg.sender.call{value: amount}("");`,
					Severity:       analyzer.Critical,
					Confidence:     analyzer.ConfidenceHigh,
					Tags:           []string{"reentrancy", "cei"},
				},
			},
		},
	}
	assertGolden(t, "text_with_findings.txt", renderText(t, results))
}

func renderText(t *testing.T, results []analyzer.AnalysisResult) string {
	t.Helper()
	var buf bytes.Buffer
	r := reporter.NewText(&buf, false, true)
	if err := r.Report(results); err != nil {
		t.Fatalf("Report: %v", err)
	}
	return buf.String()
}

func assertGolden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "golden", name)
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s: %v", path, err)
	}
	normalizedWant := strings.TrimRight(string(want), "\n")
	normalizedGot := strings.TrimRight(got, "\n")
	if normalizedWant != normalizedGot {
		t.Fatalf("golden mismatch for %s\n--- want ---\n%s\n--- got ---\n%s", name, string(want), got)
	}
}
