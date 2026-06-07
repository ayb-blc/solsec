package detectors_test

import (
	"testing"

	"github.com/ayb-blc/solsec/internal/analyzer"
	"github.com/ayb-blc/solsec/internal/detectors"
	"github.com/ayb-blc/solsec/internal/testutil"
)

func TestUninitializedOwnable_Fixtures(t *testing.T) {
	d := detectors.NewUninitializedOwnableDetector()
	for _, fixture := range testutil.LoadFixtures(t, "../../testdata/fixtures/init/ownable_*.sol") {
		fixture := fixture
		t.Run(fixture.Name, func(t *testing.T) {
			findings, err := d.Analyze(testutil.Lines(fixture.Source), fixture.Source, fixture.Path)
			if err != nil {
				t.Fatalf("Analyze: %v", err)
			}
			if len(findings) != fixture.ExpectedFindings {
				t.Fatalf("findings = %d, want %d: %#v", len(findings), fixture.ExpectedFindings, findings)
			}
			if fixture.ExpectedFindings > 0 {
				if findings[0].RuleID != "SOLSEC-INIT-004" {
					t.Fatalf("rule id = %s, want SOLSEC-INIT-004", findings[0].RuleID)
				}
				if findings[0].Severity != analyzer.High {
					t.Fatalf("severity = %s, want HIGH", findings[0].Severity)
				}
			}
		})
	}
}
