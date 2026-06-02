package accuracy_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ayb-blc/solsec/internal/analyzer"
	"github.com/ayb-blc/solsec/internal/detectors"
)

type AccuracySpec struct {
	ContractFile     string            `json:"contract_file"`
	ExpectedFindings []ExpectedFinding `json:"expected_findings"`
}

type ExpectedFinding struct {
	Detector    string `json:"detector"`
	Severity    string `json:"severity"`
	Line        int    `json:"line,omitempty"`
	MustContain string `json:"must_contain,omitempty"`
}

type AccuracyReport struct {
	TotalContracts int
	TruePositives  int     // What needs to be found, what is found
	FalsePositives int     // What should not be found, what is found
	FalseNegatives int     // What should be found, what is not found
	Precision      float64 // TP / (TP + FP)
	Recall         float64 // TP / (TP + FN)
	F1Score        float64 // 2 * P * R / (P + R)
}

func (r AccuracyReport) String() string {
	return fmt.Sprintf(
		"Contracts: %d | TP: %d | FP: %d | FN: %d | Precision: %.1f%% | Recall: %.1f%% | F1: %.2f",
		r.TotalContracts,
		r.TruePositives,
		r.FalsePositives,
		r.FalseNegatives,
		r.Precision*100,
		r.Recall*100,
		r.F1Score,
	)
}

func TestDetectorAccuracy(t *testing.T) {
	if !solcAvailable() {
		t.Skip("solc not available")
	}

	allDetectors := map[string]analyzer.Detector{
		"reentrancy": detectors.NewReentrancyDetector(),
		"tx-origin":  detectors.NewTxOriginDetector(),
	}

	for detName, det := range allDetectors {
		det := det
		detName := detName
		t.Run(detName, func(t *testing.T) {
			report := measureAccuracy(t, det, detName)
			t.Logf("\n  Accuracy Report for '%s':\n  %s", detName, report)

			if report.Precision < 0.80 {
				t.Errorf("precision too low: %.1f%% (minimum: 80%%)", report.Precision*100)
			}
			if report.Recall < 0.85 {
				t.Errorf("recall too low: %.1f%% (minimum: 85%%)", report.Recall*100)
			}
		})
	}
}

func solcAvailable() bool {
	return detectors.NewReentrancyDetector() != nil
}

func measureAccuracy(t *testing.T, det analyzer.Detector, detName string) AccuracyReport {
	t.Helper()

	var report AccuracyReport
	specDir := filepath.Join(testDataRoot(t), "expected")

	entries, err := os.ReadDir(specDir)
	if err != nil {
		t.Fatalf("cannot read spec directory: %v", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}

		specPath := filepath.Join(specDir, entry.Name())
		spec := loadSpec(t, specPath)
		report.TotalContracts++

		contractPath := filepath.Join(testDataRoot(t), "contracts", spec.ContractFile)
		content, err := os.ReadFile(contractPath)
		if err != nil {
			t.Logf("skip %s: %v", spec.ContractFile, err)
			continue
		}

		source := string(content)
		lines := strings.Split(source, "\n")
		findings, _ := det.Analyze(lines, source, contractPath)

		var detFindings []analyzer.Finding
		for _, f := range findings {
			if f.DetectorName == detName {
				detFindings = append(detFindings, f)
			}
		}

		expected := filterExpected(spec.ExpectedFindings, detName)
		matched, unmatched := matchFindings(detFindings, expected)

		report.TruePositives += len(matched)
		report.FalseNegatives += len(unmatched)                  // Expected but not found
		report.FalsePositives += len(detFindings) - len(matched) // Unexpected but found
	}

	tp := float64(report.TruePositives)
	fp := float64(report.FalsePositives)
	fn := float64(report.FalseNegatives)

	if tp+fp > 0 {
		report.Precision = tp / (tp + fp)
	}
	if tp+fn > 0 {
		report.Recall = tp / (tp + fn)
	}
	if report.Precision+report.Recall > 0 {
		report.F1Score = 2 * report.Precision * report.Recall /
			(report.Precision + report.Recall)
	}

	return report
}

func loadSpec(t *testing.T, path string) AccuracySpec {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cannot read spec %s: %v", path, err)
	}
	var spec AccuracySpec
	if err := json.Unmarshal(data, &spec); err != nil {
		t.Fatalf("cannot parse spec %s: %v", path, err)
	}
	return spec
}

func filterExpected(findings []ExpectedFinding, detName string) []ExpectedFinding {
	var result []ExpectedFinding
	for _, f := range findings {
		if f.Detector == detName {
			result = append(result, f)
		}
	}
	return result
}

func matchFindings(
	actuals []analyzer.Finding,
	expected []ExpectedFinding,
) (matched []analyzer.Finding, unmatched []ExpectedFinding) {

	used := make([]bool, len(actuals))

	for _, exp := range expected {
		foundIdx := -1
		for i, act := range actuals {
			if used[i] {
				continue
			}
			if findingMatchesSpec(act, exp) {
				foundIdx = i
				break
			}
		}

		if foundIdx >= 0 {
			used[foundIdx] = true
			matched = append(matched, actuals[foundIdx])
		} else {
			unmatched = append(unmatched, exp)
		}
	}

	return
}

func findingMatchesSpec(f analyzer.Finding, exp ExpectedFinding) bool {
	if exp.Severity != "" && f.Severity.String() != exp.Severity {
		return false
	}
	if exp.Line > 0 && f.Line != exp.Line {
		return false
	}
	if exp.MustContain != "" {
		combined := strings.ToLower(f.Title + " " + f.Description)
		if !strings.Contains(combined, strings.ToLower(exp.MustContain)) {
			return false
		}
	}
	return true
}

func testDataRoot(t *testing.T) string {
	t.Helper()
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(filename), "..", "..", "testdata")
}
