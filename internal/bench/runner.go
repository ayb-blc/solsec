// internal/bench/runner.go

package bench

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ayb-blc/solsec/internal/analyzer"
)

// Runner executes benchmark runs and collects results.
type Runner struct {
	Runs    int // number of measured runs
	Warmup  int // number of warmup runs (discarded)
	Verbose bool
}

func NewRunner() *Runner {
	return &Runner{Runs: 3, Warmup: 1}
}

// Run performs warmup + measured runs on the target directory.
func (r *Runner) Run(
	target string,
	detectors []analyzer.Detector,
	excludePatterns []string,
) (*BenchmarkResult, error) {

	allFiles, root, err := collectSolFiles(target, excludePatterns)
	if err != nil {
		return nil, fmt.Errorf("collecting files: %w", err)
	}
	if len(allFiles) == 0 {
		return nil, fmt.Errorf("no .sol files found in %s", target)
	}

	result := &BenchmarkResult{
		Target: target,
		Runs:   r.Runs,
	}

	// Warmup runs (not measured)
	for i := 0; i < r.Warmup; i++ {
		if r.Verbose {
			fmt.Fprintf(os.Stderr, "  warmup %d/%d...\n", i+1, r.Warmup)
		}
		if _, err := r.singleRun(root, allFiles, detectors); err != nil {
			return nil, err
		}
	}

	// Measured runs
	var durations []time.Duration
	for i := 0; i < r.Runs; i++ {
		if r.Verbose {
			fmt.Fprintf(os.Stderr, "  run %d/%d...\n", i+1, r.Runs)
		}
		profile, err := r.singleRun(root, allFiles, detectors)
		if err != nil {
			return nil, err
		}
		result.Profiles = append(result.Profiles, profile)
		durations = append(durations, profile.TotalDuration)
	}

	// Compute statistics
	var meanDuration time.Duration
	result.Min, result.Max, meanDuration, result.StdDev = computeStats(durations)

	// Mean profile = averaged metrics across measured runs.
	if len(result.Profiles) > 0 {
		result.Mean = meanProfile(result.Profiles)
		result.Mean.TotalDuration = meanDuration
		if meanDuration.Seconds() > 0 {
			result.Mean.FilesPerSecond = float64(result.Mean.FilesAnalyzed) / meanDuration.Seconds()
			result.Mean.FindingsPerSecond = float64(result.Mean.FindingsFound) / meanDuration.Seconds()
		}
	}

	return result, nil
}

func (r *Runner) singleRun(
	root string,
	files []string,
	detectors []analyzer.Detector,
) (*ScanProfile, error) {

	profiler, timedDetectors := NewProfiler(detectors)
	a := analyzer.New(timedDetectors, analyzer.Config{Workers: 1})
	a.BuildInheritanceGraph(root, files)

	var allFindings []analyzer.Finding
	for _, file := range files {
		fileStart := time.Now()
		result := a.AnalyzeFile(file)
		if result.Error != nil {
			continue
		}
		profiler.RecordFile(file, time.Since(fileStart), len(result.Findings))
		allFindings = append(allFindings, result.Findings...)
	}

	return profiler.Finalize(len(files), len(allFindings)), nil
}

func meanProfile(profiles []*ScanProfile) ScanProfile {
	if len(profiles) == 0 {
		return ScanProfile{}
	}

	n := len(profiles)
	mean := ScanProfile{
		FilesAnalyzed:   profiles[len(profiles)-1].FilesAnalyzed,
		FindingsFound:   profiles[len(profiles)-1].FindingsFound,
		FileTimings:     profiles[len(profiles)-1].FileTimings,
		DetectorTimings: make(map[string]*DetectorProfile),
	}

	type detectorAccumulator struct {
		name     string
		calls    int
		duration time.Duration
		findings int
	}
	detectors := make(map[string]*detectorAccumulator)

	var allocBytes uint64
	var heapBytes uint64
	var gcRuns uint32
	var allocObjs uint64

	for _, p := range profiles {
		allocBytes += p.Memory.AllocBytes
		if p.Memory.PeakHeapBytes > heapBytes {
			heapBytes = p.Memory.PeakHeapBytes
		}
		gcRuns += p.Memory.NumGC
		allocObjs += p.Memory.TotalAllocObjs

		for name, dp := range p.DetectorTimings {
			acc := detectors[name]
			if acc == nil {
				acc = &detectorAccumulator{name: name}
				detectors[name] = acc
			}
			acc.calls += dp.Calls
			acc.duration += dp.Duration
			acc.findings += dp.Findings
		}
	}

	mean.Memory = MemoryProfile{
		AllocBytes:     allocBytes / uint64(n),
		PeakHeapBytes:  heapBytes,
		NumGC:          gcRuns / uint32(n),
		TotalAllocObjs: allocObjs / uint64(n),
	}

	for name, acc := range detectors {
		duration := acc.duration / time.Duration(n)
		findings := acc.findings / n
		calls := acc.calls / n
		avgPerFile := time.Duration(0)
		if mean.FilesAnalyzed > 0 {
			avgPerFile = duration / time.Duration(mean.FilesAnalyzed)
		}
		mean.DetectorTimings[name] = &DetectorProfile{
			Name:       acc.name,
			Calls:      calls,
			Duration:   duration,
			Findings:   findings,
			AvgPerFile: avgPerFile,
		}
	}

	return mean
}

func computeStats(durations []time.Duration) (min, max, mean, stddev time.Duration) {
	if len(durations) == 0 {
		return
	}
	min = durations[0]
	max = durations[0]
	var total time.Duration
	for _, d := range durations {
		total += d
		if d < min {
			min = d
		}
		if d > max {
			max = d
		}
	}
	mean = total / time.Duration(len(durations))

	var variance float64
	for _, d := range durations {
		diff := float64(d - mean)
		variance += diff * diff
	}
	variance /= float64(len(durations))
	stddev = time.Duration(math.Sqrt(variance))
	return
}

func collectSolFiles(root string, excludePatterns []string) ([]string, string, error) {
	var files []string
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, "", err
	}
	absRoot = filepath.Clean(absRoot)

	err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			if err == nil && d.IsDir() {
				abs, absErr := filepath.Abs(path)
				if absErr != nil {
					return absErr
				}
				if filepath.Clean(abs) != absRoot && shouldSkipDefaultPath(path, d.Name()) {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if !strings.HasSuffix(path, ".sol") {
			return nil
		}
		if shouldSkipDefaultPath(path, filepath.Base(path)) {
			return nil
		}
		normalized := filepath.ToSlash(path)
		for _, pat := range excludePatterns {
			if strings.Contains(normalized, strings.TrimSuffix(pat, "/**")) {
				return nil
			}
		}
		files = append(files, path)
		return nil
	})
	sort.Strings(files)
	return files, absRoot, err
}

func shouldSkipDefaultPath(path, name string) bool {
	if strings.HasPrefix(name, ".") {
		return true
	}

	normalized := filepath.ToSlash(path)
	lowerName := strings.ToLower(name)
	lowerPath := strings.ToLower(normalized)

	if lowerName == "node_modules" || lowerName == "lib" || lowerName == "vendor" ||
		lowerName == "out" || lowerName == "artifacts" || lowerName == "cache" ||
		lowerName == "mock" || lowerName == "mocks" {
		return true
	}

	if strings.Contains(lowerPath, "/mock/") || strings.Contains(lowerPath, "/mocks/") ||
		strings.Contains(lowerPath, "/test/") || strings.Contains(lowerPath, "/tests/") {
		return true
	}

	return strings.HasSuffix(lowerName, "_test.sol") ||
		strings.HasSuffix(lowerName, ".t.sol")
}
