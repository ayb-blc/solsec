// internal/bench/types.go

package bench

import (
	"time"
)

// ScanProfile holds the performance data collected during a scan.
type ScanProfile struct {
	// Overall metrics
	TotalDuration time.Duration
	FilesAnalyzed int
	FindingsFound int

	// Throughput
	FilesPerSecond    float64
	FindingsPerSecond float64

	// Per-file breakdown (top N slowest files)
	FileTimings []FileTiming

	// Per-detector breakdown
	DetectorTimings map[string]*DetectorProfile

	// Memory (collected once at the end)
	Memory MemoryProfile
}

// FileTiming holds timing for a single file.
type FileTiming struct {
	Filepath string
	Duration time.Duration
	Findings int
}

// DetectorProfile accumulates timing across all files for one detector.
type DetectorProfile struct {
	Name       string
	Calls      int
	Duration   time.Duration
	Findings   int
	AvgPerFile time.Duration
}

// MemoryProfile holds memory statistics.
type MemoryProfile struct {
	AllocBytes     uint64 // total bytes allocated during scan
	PeakHeapBytes  uint64 // peak heap in use
	NumGC          uint32 // GC runs during scan
	TotalAllocObjs uint64 // total objects allocated
}

// BenchmarkResult is a completed benchmark with statistical summary.
type BenchmarkResult struct {
	Target string // directory scanned
	Runs   int

	Mean   ScanProfile
	Min    time.Duration
	Max    time.Duration
	StdDev time.Duration

	// Raw per-run profiles
	Profiles []*ScanProfile
}

// BaselineResult is a saved benchmark used for regression detection.
type BaselineResult struct {
	CreatedAt string
	GoVersion string
	Platform  string
	Target    string
	Mean      ScanProfile
}

// Regression is a detected performance regression vs baseline.
type Regression struct {
	Metric   string
	Baseline time.Duration
	Current  time.Duration
	Delta    time.Duration
	PctWorse float64
}
