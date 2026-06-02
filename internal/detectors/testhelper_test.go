package detectors_test

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ayb-blc/solsec/internal/analyzer"
	"github.com/ayb-blc/solsec/internal/detectors"
)

func testDataDir(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot determine test file location")
	}
	root := filepath.Join(filepath.Dir(filename), "..", "..")
	return filepath.Join(root, "testdata", "contracts")
}

type DetectorTestCase struct {
	Name string

	ContractFile string

	ExpectedFindings int

	ExpectedSeverity analyzer.Severity

	ExpectedDetector string

	ShouldFindLine int

	ShouldNotContain string
}

func RunDetectorTests(t *testing.T, d detectors.Detector, cases []DetectorTestCase) {
	t.Helper()
	base := testDataDir(t)

	for _, tc := range cases {
		tc := tc // Capture for parallel
		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()

			contractPath := filepath.Join(base, tc.ContractFile)
			findings := runDetectorOnFile(t, d, contractPath)

			assertFindings(t, tc, findings, contractPath)
		})
	}
}

func runDetectorOnFile(
	t *testing.T,
	d detectors.Detector,
	contractPath string,
) []analyzer.Finding {
	t.Helper()

	content, err := os.ReadFile(contractPath)
	if err != nil {
		if os.IsNotExist(err) {
			t.Skipf("fixture not present yet: %s", contractPath)
		}
		t.Fatalf("cannot read contract file %s: %v", contractPath, err)
	}

	source := string(content)
	lines := splitLines(source)

	findings, err := d.Analyze(lines, source, contractPath)
	if err != nil {
		if issolcError(err) {
			t.Skipf("solc not available, skipping AST-based test: %v", err)
		}
		t.Fatalf("detector error: %v", err)
	}

	return findings
}

func assertFindings(
	t *testing.T,
	tc DetectorTestCase,
	findings []analyzer.Finding,
	contractPath string,
) {
	t.Helper()

	if tc.ExpectedFindings >= 0 {
		if len(findings) != tc.ExpectedFindings {
			t.Errorf(
				"\n  contract:  %s\n  expected:  %d finding(s)\n  got:       %d finding(s)\n  findings:  %s",
				contractPath,
				tc.ExpectedFindings,
				len(findings),
				formatFindings(findings),
			)
		}
	} else if tc.ExpectedFindings == -1 && len(findings) == 0 {
		t.Errorf(
			"\n  contract: %s\n  expected: at least 1 finding\n  got:      0 findings",
			contractPath,
		)
	}

	if tc.ExpectedSeverity != analyzer.Info && len(findings) > 0 {
		for _, f := range findings {
			if f.Severity != tc.ExpectedSeverity {
				t.Errorf(
					"\n  finding:  %q\n  expected severity: %s\n  got severity:      %s",
					f.Title, tc.ExpectedSeverity, f.Severity,
				)
			}
		}
	}

	if tc.ExpectedDetector != "" {
		for _, f := range findings {
			if f.DetectorName != tc.ExpectedDetector {
				t.Errorf(
					"\n  expected detector: %q\n  got detector:      %q",
					tc.ExpectedDetector, f.DetectorName,
				)
			}
		}
	}

	if tc.ShouldFindLine > 0 {
		found := false
		for _, f := range findings {
			if f.Line == tc.ShouldFindLine {
				found = true
				break
			}
		}
		if !found {
			t.Errorf(
				"\n  expected finding at line %d\n  actual lines: %v",
				tc.ShouldFindLine,
				findingLines(findings),
			)
		}
	}

	if tc.ShouldNotContain != "" {
		for _, f := range findings {
			if containsString(f.Title+f.Description, tc.ShouldNotContain) {
				t.Errorf(
					"\n  unexpected finding containing %q\n  finding: %s",
					tc.ShouldNotContain, f.Title,
				)
			}
		}
	}
}

func splitLines(source string) []string {
	return strings.Split(source, "\n")
}

func issolcError(err error) bool {
	return strings.Contains(err.Error(), "solc") ||
		strings.Contains(err.Error(), "executable file not found")
}

func formatFindings(findings []analyzer.Finding) string {
	if len(findings) == 0 {
		return "(none)"
	}
	parts := make([]string, len(findings))
	for i, f := range findings {
		parts[i] = fmt.Sprintf("\n    [%s] %s (line %d)", f.Severity, f.Title, f.Line)
	}
	return strings.Join(parts, "")
}

func findingLines(findings []analyzer.Finding) []int {
	lines := make([]int, len(findings))
	for i, f := range findings {
		lines[i] = f.Line
	}
	return lines
}

func containsString(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}
