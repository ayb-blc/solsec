package detectors_test

import (
	"testing"

	"github.com/ayb-blc/solsec/internal/analyzer"
	"github.com/ayb-blc/solsec/internal/detectors"
	"github.com/ayb-blc/solsec/internal/testutil"
)

func TestDetectorFixtureMatrix(t *testing.T) {
	cases := []struct {
		name     string
		pattern  string
		detector analyzer.Detector
	}{
		{"reentrancy", "../../testdata/fixtures/reentrancy/*.sol", detectors.NewReentrancyDetectorV2()},
		{"unchecked-call", "../../testdata/fixtures/unchecked_call/*.sol", detectors.NewUncheckedCallDetectorV2()},
		{"integer-overflow", "../../testdata/fixtures/integer_overflow/*.sol", detectors.NewIntegerOverflowDetectorV2()},
		{"access-control", "../../testdata/fixtures/access_control/*.sol", detectors.NewAccessControlDetector()},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			for _, fixture := range testutil.LoadFixtures(t, tc.pattern) {
				fixture := fixture
				t.Run(fixture.Name, func(t *testing.T) {
					findings, err := tc.detector.Analyze(testutil.Lines(fixture.Source), fixture.Source, fixture.Path)
					if err != nil {
						t.Fatalf("Analyze: %v", err)
					}
					if fixture.ExpectedFindings == 0 && len(findings) != 0 {
						t.Fatalf("expected no findings, got %d: %#v", len(findings), findings)
					}
					if fixture.ExpectedFindings > 0 && len(findings) == 0 {
						t.Fatalf("expected at least one finding")
					}
				})
			}
		})
	}
}
