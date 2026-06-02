package formal_test

import (
	"testing"

	"github.com/ayb-blc/solsec/internal/analyzer"
	"github.com/ayb-blc/solsec/internal/formal"
)

func TestSeedGenerator_ReentrancyFinding(t *testing.T) {
	sg := formal.NewSeedGenerator()

	findings := []analyzer.Finding{
		{
			DetectorName: "reentrancy",
			Title:        "Potential reentrancy in function 'withdraw'",
			Description:  "External call before state update",
			Filepath:     "/contracts/Vault.sol",
			Line:         42,
			Severity:     analyzer.Critical,
			Confidence:   analyzer.ConfidenceHigh,
		},
	}

	targets := sg.Generate(findings)

	if len(targets) == 0 {
		t.Fatal("expected at least one fuzz target from reentrancy finding")
	}

	target := targets[0]
	if target.Priority != formal.PriorityCritical {
		t.Errorf("priority = %v, want PriorityCritical", target.Priority)
	}
	if len(target.Properties) == 0 {
		t.Error("expected at least one property")
	}
	if len(target.SeedValues) == 0 {
		t.Error("expected seed values for reentrancy")
	}

	prop := target.Properties[0]
	if prop.SolidityCode == "" {
		t.Error("expected Solidity property code for Echidna")
	}
	if prop.Kind != formal.PropertyReentrancy {
		t.Errorf("property kind = %v, want PropertyReentrancy", prop.Kind)
	}
}

func TestSeedGenerator_AccessControlFinding(t *testing.T) {
	sg := formal.NewSeedGenerator()

	findings := []analyzer.Finding{
		{
			DetectorName: "access-control",
			Title:        "Missing access control on function 'mint'",
			Filepath:     "/contracts/Token.sol",
			Severity:     analyzer.Critical,
		},
	}

	targets := sg.Generate(findings)
	if len(targets) == 0 {
		t.Fatal("expected target for access-control finding")
	}

	prop := targets[0].Properties[0]
	if prop.Kind != formal.PropertyAccessControl {
		t.Errorf("property kind = %v, want PropertyAccessControl", prop.Kind)
	}
}

func TestSeedGenerator_ArithmeticFinding(t *testing.T) {
	sg := formal.NewSeedGenerator()

	findings := []analyzer.Finding{
		{
			DetectorName: "integer-overflow",
			Title:        "Potential integer overflow in unchecked block",
			Filepath:     "/contracts/Math.sol",
			Severity:     analyzer.High,
		},
	}

	targets := sg.Generate(findings)
	if len(targets) == 0 {
		t.Fatal("expected target for integer-overflow finding")
	}

	seeds := targets[0].SeedValues
	if len(seeds) == 0 {
		t.Error("expected seed values for arithmetic finding")
	}

	hasMaxSeed := false
	for _, sv := range seeds {
		if len(sv.Value) > 60 {
			hasMaxSeed = true
			break
		}
	}
	if !hasMaxSeed {
		t.Error("expected max uint256 seed value for arithmetic overflow testing")
	}
}

func TestSeedGenerator_UnknownDetector_ReturnsNoTarget(t *testing.T) {
	sg := formal.NewSeedGenerator()

	findings := []analyzer.Finding{
		{
			DetectorName: "some-unknown-detector",
			Filepath:     "/contracts/X.sol",
			Severity:     analyzer.High,
		},
	}

	targets := sg.Generate(findings)
	if len(targets) != 0 {
		t.Errorf("expected no targets for unknown detector, got %d", len(targets))
	}
}

func TestSeedGenerator_SortsByPriority(t *testing.T) {
	sg := formal.NewSeedGenerator()

	findings := []analyzer.Finding{
		{DetectorName: "reentrancy", Filepath: "/a.sol", Severity: analyzer.Low},
		{DetectorName: "reentrancy", Filepath: "/b.sol", Severity: analyzer.Critical},
		{DetectorName: "access-control", Filepath: "/c.sol", Severity: analyzer.High},
	}

	targets := sg.Generate(findings)
	if len(targets) < 2 {
		t.Skip("not enough targets to check ordering")
	}

	if targets[0].Priority < targets[len(targets)-1].Priority {
		t.Error("targets should be sorted by priority (highest first)")
	}
}

func TestRunnerOptions_Default(t *testing.T) {
	opts := formal.DefaultRunnerOptions()
	if opts.Timeout == 0 {
		t.Error("default timeout should not be zero")
	}
	if opts.MaxTargets == 0 {
		t.Error("default max targets should not be zero")
	}
}

func TestRunner_CheckAvailability(t *testing.T) {
	opts := formal.DefaultRunnerOptions()
	runner := formal.NewRunner(opts)
	avail := runner.CheckAvailability()

	for _, tool := range opts.Tools {
		if _, ok := avail[tool]; !ok {
			t.Errorf("availability missing for tool %s", tool)
		}
	}
}

func TestFormalPipeline_DryRun(t *testing.T) {
	tmpDir := t.TempDir()
	opts := formal.PipelineOpts{
		RunnerOptions: formal.RunnerOptions{
			Tools:        []formal.Tool{formal.ToolEchidna, formal.ToolManticore},
			DryRun:       true,
			MaxTargets:   5,
			OnlyPriority: formal.PriorityLow,
		},
		OutputDir: tmpDir,
	}

	pipeline := formal.NewFormalPipeline(opts)

	findings := []analyzer.Finding{
		{
			DetectorName: "reentrancy",
			Title:        "Reentrancy in 'withdraw'",
			Filepath:     "/tmp/test.sol",
			Line:         10,
			Severity:     analyzer.Critical,
			Confidence:   analyzer.ConfidenceHigh,
		},
	}

	result, err := pipeline.Run(findings)
	if err != nil {
		t.Fatalf("pipeline.Run: %v", err)
	}

	if len(result.Targets) == 0 {
		t.Error("expected targets to be generated")
	}

	if len(result.VerificationResults) > 0 {
		t.Error("dry run should not produce verification results")
	}
}

func TestSummary_Empty(t *testing.T) {
	s := formal.Summary(nil)
	if s.Total != 0 {
		t.Errorf("empty summary total = %d, want 0", s.Total)
	}
	if s.HasViolations() {
		t.Error("empty summary should not have violations")
	}
}

func TestSummary_WithResults(t *testing.T) {
	results := []*formal.VerificationResult{
		{Status: formal.StatusSafe},
		{Status: formal.StatusViolation, Violations: []formal.Violation{
			{PropertyName: "test", Severity: analyzer.Critical},
		}},
		{Status: formal.StatusTimeout},
	}

	s := formal.Summary(results)
	if s.Total != 3 {
		t.Errorf("total = %d, want 3", s.Total)
	}
	if s.Safe != 1 {
		t.Errorf("safe = %d, want 1", s.Safe)
	}
	if s.Violations != 1 {
		t.Errorf("violations = %d, want 1", s.Violations)
	}
	if s.Timeouts != 1 {
		t.Errorf("timeouts = %d, want 1", s.Timeouts)
	}
	if !s.HasViolations() {
		t.Error("should have violations")
	}
}

func TestPropertyKind_Constants(t *testing.T) {
	kinds := []formal.PropertyKind{
		formal.PropertyReentrancy,
		formal.PropertyAccessControl,
		formal.PropertyArithmetic,
		formal.PropertyETHBalance,
		formal.PropertyStateConsistency,
		formal.PropertyCustom,
	}
	seen := make(map[formal.PropertyKind]bool)
	for _, k := range kinds {
		if seen[k] {
			t.Errorf("duplicate PropertyKind: %v", k)
		}
		seen[k] = true
	}
}

func TestCoverageInfo_LinePercent(t *testing.T) {
	ci := &formal.CoverageInfo{LinesCovered: 75, LinesTotal: 100}
	if ci.LinePercent() != 75.0 {
		t.Errorf("LinePercent = %v, want 75.0", ci.LinePercent())
	}

	zero := &formal.CoverageInfo{}
	if zero.LinePercent() != 0 {
		t.Error("zero total should return 0 percent")
	}
}
