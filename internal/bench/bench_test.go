// internal/bench/bench_test.go

package bench_test

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ayb-blc/solsec/internal/bench"
	"github.com/ayb-blc/solsec/internal/detectors"
)

// ─── Go benchmark tests ───────────────────────────────────────────────────────

func BenchmarkDetector_Reentrancy(b *testing.B) {
	source := syntheticVaultSource(50) // 50 functions
	lines := splitLines(source)

	d := detectors.NewReentrancyDetector()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = d.Analyze(lines, source, "bench.sol")
	}

	b.ReportAllocs()
}

func BenchmarkDetector_AccessControl(b *testing.B) {
	source := syntheticVaultSource(50)
	lines := splitLines(source)

	d := detectors.NewAccessControlDetector()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = d.Analyze(lines, source, "bench.sol")
	}
	b.ReportAllocs()
}

func BenchmarkDetector_ERC4626(b *testing.B) {
	source := syntheticVaultSource(20)
	lines := splitLines(source)

	d := detectors.NewERC4626InflationDetector()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = d.Analyze(lines, source, "bench.sol")
	}
	b.ReportAllocs()
}

func BenchmarkAnalyzer_AllDetectors_SmallFile(b *testing.B) {
	source := syntheticVaultSource(10)
	lines := splitLines(source)

	allDetectors := detectors.DefaultDetectors()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		for _, d := range allDetectors {
			_, _ = d.Analyze(lines, source, "bench.sol")
		}
	}
	b.ReportAllocs()
}

func BenchmarkAnalyzer_AllDetectors_LargeFile(b *testing.B) {
	source := syntheticVaultSource(200) // 200 functions
	lines := splitLines(source)

	allDetectors := detectors.DefaultDetectors()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		for _, d := range allDetectors {
			_, _ = d.Analyze(lines, source, "bench.sol")
		}
	}
	b.ReportAllocs()
}

// ─── Runner tests ─────────────────────────────────────────────────────────────

func TestRunner_BasicBenchmark(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping benchmark in short mode")
	}

	dir := t.TempDir()
	for i := 0; i < 5; i++ {
		writeTestFile(t, dir, fmt.Sprintf("contract%d.sol", i),
			syntheticVaultSource(10))
	}

	runner := &bench.Runner{Runs: 2, Warmup: 1}
	result, err := runner.Run(dir, detectors.DefaultDetectors(), nil)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	if result.Runs != 2 {
		t.Errorf("runs = %d, want 2", result.Runs)
	}
	if result.Mean.FilesAnalyzed != 5 {
		t.Errorf("files = %d, want 5", result.Mean.FilesAnalyzed)
	}
	if result.Mean.TotalDuration == 0 {
		t.Error("duration should be > 0")
	}
	if len(result.Mean.DetectorTimings) == 0 {
		t.Error("detector timings should be populated")
	}
}

func TestRunner_BaselineSaveLoad(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "vault.sol", syntheticVaultSource(5))

	runner := &bench.Runner{Runs: 1, Warmup: 0}
	result, err := runner.Run(dir, detectors.DefaultDetectors()[:2], nil)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	baselinePath := filepath.Join(t.TempDir(), "baseline.json")
	if err := bench.SaveBaseline(result, baselinePath); err != nil {
		t.Fatalf("SaveBaseline: %v", err)
	}

	loaded, err := bench.LoadBaseline(baselinePath)
	if err != nil {
		t.Fatalf("LoadBaseline: %v", err)
	}

	if loaded.Target != result.Target {
		t.Errorf("target = %q, want %q", loaded.Target, result.Target)
	}
}

func TestDetectRegressions_NoRegression(t *testing.T) {
	result := &bench.BenchmarkResult{
		Mean: bench.ScanProfile{
			TotalDuration: 100 * time.Millisecond,
			DetectorTimings: map[string]*bench.DetectorProfile{
				"reentrancy": {Name: "reentrancy", Duration: 50 * time.Millisecond},
			},
		},
	}
	baseline := &bench.BaselineResult{
		Mean: bench.ScanProfile{
			TotalDuration: 95 * time.Millisecond,
			DetectorTimings: map[string]*bench.DetectorProfile{
				"reentrancy": {Name: "reentrancy", Duration: 48 * time.Millisecond},
			},
		},
	}

	regressions := bench.DetectRegressions(result, baseline, 10.0)
	if len(regressions) != 0 {
		t.Errorf("5%% worse = no regression at 10%% threshold, got %d", len(regressions))
	}
}

func TestDetectRegressions_WithRegression(t *testing.T) {
	result := &bench.BenchmarkResult{
		Mean: bench.ScanProfile{
			TotalDuration: 200 * time.Millisecond, // 2x slower
		},
	}
	baseline := &bench.BaselineResult{
		Mean: bench.ScanProfile{
			TotalDuration: 100 * time.Millisecond,
		},
	}

	regressions := bench.DetectRegressions(result, baseline, 10.0)
	if len(regressions) == 0 {
		t.Error("2x slower should be detected as regression")
	}
	if regressions[0].PctWorse < 90 {
		t.Errorf("pct worse = %.1f%%, want ~100%%", regressions[0].PctWorse)
	}
}

func TestTimedDetector_RecordsMetrics(t *testing.T) {
	inner := detectors.NewReentrancyDetector()
	td := bench.NewTimedDetector(inner)

	source := syntheticVaultSource(5)
	lines := splitLines(source)

	for i := 0; i < 3; i++ {
		_, _ = td.Analyze(lines, source, "t.sol")
	}

	prof := td.Profile()
	if prof.Calls != 3 {
		t.Errorf("calls = %d, want 3", prof.Calls)
	}
	if prof.Duration == 0 {
		t.Error("duration should be > 0")
	}
	if prof.AvgPerFile == 0 {
		t.Error("avg per file should be > 0")
	}
}

func TestRenderText_DetectorTable(t *testing.T) {
	result := &bench.BenchmarkResult{
		Target: "/tmp/contracts",
		Runs:   3,
		Mean: bench.ScanProfile{
			TotalDuration:  2 * time.Second,
			FilesAnalyzed:  20,
			FindingsFound:  1,
			FilesPerSecond: 10,
			DetectorTimings: map[string]*bench.DetectorProfile{
				"reentrancy": {
					Name:       "reentrancy",
					Duration:   900 * time.Millisecond,
					AvgPerFile: 45 * time.Millisecond,
					Findings:   1,
				},
				"tx-origin": {
					Name:       "tx-origin",
					Duration:   100 * time.Millisecond,
					AvgPerFile: 5 * time.Millisecond,
					Findings:   0,
				},
			},
		},
		Min:    1900 * time.Millisecond,
		Max:    2100 * time.Millisecond,
		StdDev: 100 * time.Millisecond,
	}

	var out bytes.Buffer
	bench.RenderText(result, &out)
	text := out.String()

	for _, want := range []string{"By Detector:", "share", "profile", "[############]", "[#...........]"} {
		if !strings.Contains(text, want) {
			t.Fatalf("rendered output missing %q:\n%s", want, text)
		}
	}
}

// ─── synthetic fixtures ───────────────────────────────────────────────────────

// syntheticVaultSource generates a realistic DeFi vault contract
// with n functions, giving us a controllable-size benchmark target.
func syntheticVaultSource(n int) string {
	var sb strings.Builder
	sb.WriteString(`pragma solidity ^0.8.0;
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract SyntheticVault is Ownable, ReentrancyGuard {
    mapping(address => uint256) public balances;
    mapping(address => uint256) public nonces;
    uint256 public totalDeposits;
    address public treasury;
    uint256 public fee;
    bool private _locked;

	`)
	for i := 0; i < n; i++ {
		switch i % 5 {
		case 0:
			// Vulnerable function (reentrancy candidate)
			fmt.Fprintf(&sb, `
    function withdraw%d(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        (bool ok,) = msg.sender.call{value: amount}("");
        balances[msg.sender] -= amount;
        require(ok);
    }
`, i)
		case 1:
			// Safe function (CEI compliant)
			fmt.Fprintf(&sb, `
    function deposit%d() external payable nonReentrant {
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
        emit Deposit%d(msg.sender, msg.value);
    }
`, i, i)
		case 2:
			// Admin function
			fmt.Fprintf(&sb, `
    function setFee%d(uint256 newFee) external onlyOwner {
        fee = newFee;
    }
`, i)
		default:
			// View function
			fmt.Fprintf(&sb, `
    function getBalance%d(address user) external view returns (uint256) {
        return balances[user];
    }
`, i)
		}
	}
	sb.WriteString("}\n")
	return sb.String()
}

func splitLines(s string) []string {
	return strings.Split(s, "\n")
}

func writeTestFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0644); err != nil {
		t.Fatalf("writeFile: %v", err)
	}
}
