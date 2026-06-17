// internal/bench/renderer.go

package bench

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"
)

// RenderText writes a human-readable benchmark report to w.
func RenderText(result *BenchmarkResult, w io.Writer) {
	p := result.Mean
	files := p.FilesAnalyzed
	total := result.Mean.TotalDuration

	fmt.Fprintf(w, "\n  solsec — Performance Benchmark\n")
	fmt.Fprintf(w, "  %s\n\n", strings.Repeat("─", 56))

	// Overview
	fmt.Fprintf(w, "  Target:         %s\n", result.Target)
	fmt.Fprintf(w, "  Files:          %d\n", files)
	fmt.Fprintf(w, "  Findings:       %d\n", p.FindingsFound)
	fmt.Fprintf(w, "  Runs:           %d\n\n", result.Runs)

	// Timing
	fmt.Fprintf(w, "  %-20s %s\n", "Total (mean):", formatDuration(total))
	fmt.Fprintf(w, "  %-20s %s\n", "Min:", formatDuration(result.Min))
	fmt.Fprintf(w, "  %-20s %s\n", "Max:", formatDuration(result.Max))
	fmt.Fprintf(w, "  %-20s %s\n\n", "StdDev:", formatDuration(result.StdDev))

	// Throughput
	fmt.Fprintf(w, "  %-20s %.1f files/sec\n", "Throughput:", p.FilesPerSecond)
	if files > 0 {
		perFile := total / time.Duration(files)
		fmt.Fprintf(w, "  %-20s %s/file\n\n", "Avg per file:", formatDuration(perFile))
	}

	// Per-detector breakdown
	if len(p.DetectorTimings) > 0 {
		fmt.Fprintf(w, "  By Detector:\n")
		fmt.Fprintf(w, "  %-32s %7s %7s %8s %5s  %s\n",
			"detector", "total", "share", "avg/file", "finds", "profile")
		fmt.Fprintf(w, "  %s\n", strings.Repeat("─", 80))

		sorted := sortedDetectors(p.DetectorTimings)
		detectorTotal := totalDetectorDuration(sorted)
		for _, dp := range sorted {
			bar := miniBar(dp.Duration, sorted[0].Duration)
			share := durationShare(dp.Duration, detectorTotal)
			fmt.Fprintf(w, "  %-32s %7s %6.1f%% %8s %5d  %s\n",
				dp.Name,
				formatDuration(dp.Duration),
				share,
				formatDuration(dp.AvgPerFile),
				dp.Findings,
				bar,
			)
		}
		fmt.Fprintln(w)
	}

	// Slowest files
	if len(p.FileTimings) > 0 {
		fmt.Fprintf(w, "  Slowest Files:\n")
		limit := 5
		if len(p.FileTimings) < limit {
			limit = len(p.FileTimings)
		}
		for i := 0; i < limit; i++ {
			ft := p.FileTimings[i]
			name := ft.Filepath
			if len(name) > 50 {
				name = "..." + name[len(name)-47:]
			}
			fmt.Fprintf(w, "    %8s  %s\n", formatDuration(ft.Duration), name)
		}
		fmt.Fprintln(w)
	}

	// Memory
	mem := p.Memory
	fmt.Fprintf(w, "  Memory:\n")
	fmt.Fprintf(w, "    %-20s %s\n", "Allocated:", formatBytes(mem.AllocBytes))
	fmt.Fprintf(w, "    %-20s %s\n", "Peak heap:", formatBytes(mem.PeakHeapBytes))
	fmt.Fprintf(w, "    %-20s %d\n", "GC runs:", mem.NumGC)
	fmt.Fprintln(w)
}

// RenderRegressions writes a regression comparison to w.
func RenderRegressions(regressions []Regression, w io.Writer) {
	if len(regressions) == 0 {
		fmt.Fprintln(w, "  ✅ No performance regressions detected.")
		return
	}
	fmt.Fprintln(w, "\n  ⚠  Performance regressions detected:")
	for _, r := range regressions {
		fmt.Fprintf(w, "    %-30s  baseline: %s  current: %s  (+%.1f%%)\n",
			r.Metric,
			formatDuration(r.Baseline),
			formatDuration(r.Current),
			r.PctWorse,
		)
	}
}

// SaveBaseline writes a BenchmarkResult as a JSON baseline file.
func SaveBaseline(result *BenchmarkResult, path string) error {
	baseline := BaselineResult{
		CreatedAt: time.Now().Format(time.RFC3339),
		GoVersion: runtime.Version(),
		Platform:  runtime.GOOS + "/" + runtime.GOARCH,
		Target:    result.Target,
		Mean:      result.Mean,
	}
	data, err := json.MarshalIndent(baseline, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// LoadBaseline reads a saved baseline file.
func LoadBaseline(path string) (*BaselineResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var b BaselineResult
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, err
	}
	return &b, nil
}

// DetectRegressions compares a result against a baseline.
// A regression is flagged when performance degrades by more than threshold%.
func DetectRegressions(result *BenchmarkResult, baseline *BaselineResult, thresholdPct float64) []Regression {
	var regressions []Regression
	const (
		minRegressionDelta    = 50 * time.Millisecond
		minDetectorBaseline   = 100 * time.Millisecond
		minTotalDurationDelta = 100 * time.Millisecond
	)

	check := func(metric string, baseline, current, minBaseline, minDelta time.Duration) {
		if baseline == 0 {
			return
		}
		if baseline < minBaseline {
			return
		}
		delta := current - baseline
		if delta < minDelta {
			return
		}
		pct := float64(current-baseline) / float64(baseline) * 100
		if pct > thresholdPct {
			regressions = append(regressions, Regression{
				Metric:   metric,
				Baseline: baseline,
				Current:  current,
				Delta:    delta,
				PctWorse: pct,
			})
		}
	}

	check("total_duration",
		baseline.Mean.TotalDuration,
		result.Mean.TotalDuration,
		0,
		minTotalDurationDelta,
	)

	// Per-detector regressions
	for name, current := range result.Mean.DetectorTimings {
		if base, ok := baseline.Mean.DetectorTimings[name]; ok {
			check("detector:"+name,
				base.Duration,
				current.Duration,
				minDetectorBaseline,
				minRegressionDelta,
			)
		}
	}

	return regressions
}

// ── helpers ───────────────────────────────────────────────────────────────────

func sortedDetectors(m map[string]*DetectorProfile) []*DetectorProfile {
	var dps []*DetectorProfile
	for _, dp := range m {
		dps = append(dps, dp)
	}
	sort.Slice(dps, func(i, j int) bool {
		return dps[i].Duration > dps[j].Duration
	})
	return dps
}

func totalDetectorDuration(detectors []*DetectorProfile) time.Duration {
	var total time.Duration
	for _, dp := range detectors {
		total += dp.Duration
	}
	return total
}

func durationShare(value, total time.Duration) float64 {
	if total == 0 {
		return 0
	}
	return float64(value) / float64(total) * 100
}

func formatDuration(d time.Duration) string {
	if d < time.Millisecond {
		return fmt.Sprintf("%dµs", d.Microseconds())
	}
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	return fmt.Sprintf("%.2fs", d.Seconds())
}

func formatBytes(b uint64) string {
	const (
		KB = 1024
		MB = 1024 * KB
		GB = 1024 * MB
	)
	switch {
	case b >= GB:
		return fmt.Sprintf("%.1f GB", float64(b)/GB)
	case b >= MB:
		return fmt.Sprintf("%.1f MB", float64(b)/MB)
	case b >= KB:
		return fmt.Sprintf("%.1f KB", float64(b)/KB)
	default:
		return fmt.Sprintf("%d B", b)
	}
}

func miniBar(value, max time.Duration) string {
	if max == 0 {
		return "[............]"
	}
	const width = 12
	filled := int(float64(value) / float64(max) * width)
	if value > 0 && filled == 0 {
		filled = 1
	}
	if filled > width {
		filled = width
	}
	return "[" + strings.Repeat("#", filled) + strings.Repeat(".", width-filled) + "]"
}
