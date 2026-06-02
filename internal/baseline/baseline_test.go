package baseline_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/ayb-blc/solsec/internal/analyzer"
	"github.com/ayb-blc/solsec/internal/baseline"
	"github.com/ayb-blc/solsec/internal/exitcode"
	"github.com/ayb-blc/solsec/internal/rules"
)

func sampleResults() []analyzer.AnalysisResult {
	return []analyzer.AnalysisResult{
		{
			Filepath: "/project/contracts/Vault.sol",
			Findings: []analyzer.Finding{
				{
					RuleID:       rules.IDReentrancy001,
					DetectorName: "reentrancy",
					Title:        "Reentrancy in 'withdraw'",
					Filepath:     "/project/contracts/Vault.sol",
					Line:         42,
					CodeSnippet:  "msg.sender.call{value: amount}(\"\")",
					Severity:     analyzer.Critical,
					Confidence:   analyzer.ConfidenceHigh,
				},
				{
					RuleID:       rules.IDTxOrigin001,
					DetectorName: "tx-origin",
					Title:        "tx.origin authentication",
					Filepath:     "/project/contracts/Vault.sol",
					Line:         60,
					Severity:     analyzer.High,
					Confidence:   analyzer.ConfidenceHigh,
				},
			},
		},
	}
}

func TestBaseline_Create(t *testing.T) {
	results := sampleResults()
	b := baseline.Create(results, "/project", "0.1.0")

	if b.Version == "" {
		t.Error("baseline version should not be empty")
	}
	if b.TotalFindings != 2 {
		t.Errorf("total findings = %d, want 2", b.TotalFindings)
	}
	if len(b.Findings) != 2 {
		t.Errorf("findings map len = %d, want 2", len(b.Findings))
	}
}

func TestBaseline_SaveAndLoad(t *testing.T) {
	results := sampleResults()
	b := baseline.Create(results, "/project", "0.1.0")

	f, err := os.CreateTemp("", "baseline_test_*.json")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	defer os.Remove(f.Name())

	if err := b.SaveToFile(f.Name()); err != nil {
		t.Fatalf("SaveToFile: %v", err)
	}

	loaded, err := baseline.LoadFromFile(f.Name())
	if err != nil {
		t.Fatalf("LoadFromFile: %v", err)
	}

	if loaded.TotalFindings != b.TotalFindings {
		t.Errorf("loaded TotalFindings = %d, want %d",
			loaded.TotalFindings, b.TotalFindings)
	}
	if len(loaded.Findings) != len(b.Findings) {
		t.Errorf("loaded Findings len = %d, want %d",
			len(loaded.Findings), len(b.Findings))
	}
}

func TestBaseline_Diff_AllExisting(t *testing.T) {
	results := sampleResults()
	b := baseline.Create(results, "/project", "0.1.0")

	diff := baseline.Diff(results, b, "/project")

	if len(diff.New) != 0 {
		t.Errorf("expected 0 new findings, got %d", len(diff.New))
	}
	if len(diff.Existing) != 2 {
		t.Errorf("expected 2 existing findings, got %d", len(diff.Existing))
	}
}

func TestBaseline_Diff_NewFinding(t *testing.T) {
	oldResults := []analyzer.AnalysisResult{{
		Filepath: "/project/contracts/Vault.sol",
		Findings: []analyzer.Finding{sampleResults()[0].Findings[0]},
	}}
	b := baseline.Create(oldResults, "/project", "0.1.0")

	diff := baseline.Diff(sampleResults(), b, "/project")

	if len(diff.New) != 1 {
		t.Errorf("expected 1 new finding, got %d", len(diff.New))
	}
	if len(diff.Existing) != 1 {
		t.Errorf("expected 1 existing finding, got %d", len(diff.Existing))
	}
}

func TestBaseline_Diff_ResolvedFinding(t *testing.T) {
	b := baseline.Create(sampleResults(), "/project", "0.1.0")

	reducedResults := []analyzer.AnalysisResult{{
		Filepath: "/project/contracts/Vault.sol",
		Findings: []analyzer.Finding{sampleResults()[0].Findings[0]},
	}}

	diff := baseline.Diff(reducedResults, b, "/project")

	if len(diff.Resolved) != 1 {
		t.Errorf("expected 1 resolved finding, got %d", len(diff.Resolved))
	}
}

func TestBaseline_Contains(t *testing.T) {
	results := sampleResults()
	b := baseline.Create(results, "/project", "0.1.0")

	for id := range b.Findings {
		if !b.Contains(id) {
			t.Errorf("baseline.Contains(%q) returned false for existing ID", id)
		}
		break
	}

	if b.Contains("SOLSEC-NONEXISTENT-00000000") {
		t.Error("baseline.Contains should return false for unknown fingerprint")
	}
}

func TestBaseline_FilterAboveThreshold(t *testing.T) {
	diff := &baseline.DiffResult{
		New: []analyzer.Finding{
			{Severity: analyzer.Critical, Title: "Critical issue"},
			{Severity: analyzer.High, Title: "High issue"},
			{Severity: analyzer.Medium, Title: "Medium issue"},
			{Severity: analyzer.Low, Title: "Low issue"},
		},
	}

	aboveHigh := diff.FilterAboveThreshold(analyzer.High)
	if len(aboveHigh) != 2 {
		t.Errorf("above High threshold: got %d, want 2 (critical+high)",
			len(aboveHigh))
	}

	aboveCritical := diff.FilterAboveThreshold(analyzer.Critical)
	if len(aboveCritical) != 1 {
		t.Errorf("above Critical threshold: got %d, want 1",
			len(aboveCritical))
	}
}

func TestExitCode_FromResults(t *testing.T) {
	from := exitcode.FromResults

	if code := from([]analyzer.AnalysisResult{{}}, analyzer.Medium); code != exitcode.Success {
		t.Errorf("empty results: exit code = %d, want %d", code, exitcode.Success)
	}

	results := []analyzer.AnalysisResult{{
		Findings: []analyzer.Finding{{Severity: analyzer.Low}},
	}}
	if code := from(results, analyzer.Medium); code != exitcode.Success {
		t.Errorf("below threshold: exit code = %d, want %d", code, exitcode.Success)
	}

	results = []analyzer.AnalysisResult{{
		Findings: []analyzer.Finding{{Severity: analyzer.Critical}},
	}}
	if code := from(results, analyzer.Medium); code != exitcode.Finding {
		t.Errorf("above threshold: exit code = %d, want %d", code, exitcode.Finding)
	}

	results = []analyzer.AnalysisResult{{
		Error: fmt.Errorf("parse failed"),
	}}
	if code := from(results, analyzer.Medium); code != exitcode.AnalysisError {
		t.Errorf("with error: exit code = %d, want %d", code, exitcode.AnalysisError)
	}
}
