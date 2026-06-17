// internal/bench/profiler.go

package bench

import (
	"runtime"
	"sync"
	"time"

	"github.com/ayb-blc/solsec/internal/analyzer"
	"github.com/ayb-blc/solsec/internal/inheritancegraph"
)

// TimedDetector wraps a Detector to record per-call timing.
type TimedDetector struct {
	inner   analyzer.Detector
	profile *DetectorProfile
	mu      sync.Mutex
}

func NewTimedDetector(d analyzer.Detector) *TimedDetector {
	return &TimedDetector{
		inner: d,
		profile: &DetectorProfile{
			Name: d.Name(),
		},
	}
}

func (td *TimedDetector) Name() string                { return td.inner.Name() }
func (td *TimedDetector) Severity() analyzer.Severity { return td.inner.Severity() }
func (td *TimedDetector) Description() string         { return td.inner.Description() }

func (td *TimedDetector) Analyze(
	lines []string,
	source string,
	filepath string,
) ([]analyzer.Finding, error) {

	start := time.Now()
	findings, err := td.inner.Analyze(lines, source, filepath)
	elapsed := time.Since(start)

	td.record(elapsed, len(findings))
	return findings, err
}

// AnalyzeWithGraph preserves graph-aware detector behavior while timing it.
func (td *TimedDetector) AnalyzeWithGraph(
	lines []string,
	source string,
	filepath string,
	graph *inheritancegraph.Graph,
) ([]analyzer.Finding, error) {
	graphDetector, ok := td.inner.(analyzer.GraphAwareDetector)
	if !ok {
		return td.Analyze(lines, source, filepath)
	}

	start := time.Now()
	findings, err := graphDetector.AnalyzeWithGraph(lines, source, filepath, graph)
	elapsed := time.Since(start)

	td.record(elapsed, len(findings))
	return findings, err
}

func (td *TimedDetector) Profile() DetectorProfile {
	td.mu.Lock()
	defer td.mu.Unlock()
	return *td.profile
}

func (td *TimedDetector) record(elapsed time.Duration, findings int) {
	td.mu.Lock()
	td.profile.Calls++
	td.profile.Duration += elapsed
	td.profile.Findings += findings
	if td.profile.Calls > 0 {
		td.profile.AvgPerFile = td.profile.Duration /
			time.Duration(td.profile.Calls)
	}
	td.mu.Unlock()
}

// Profiler collects a ScanProfile during a scan run.
type Profiler struct {
	start       time.Time
	memBefore   runtime.MemStats
	fileTimings []FileTiming
	detectors   []*TimedDetector
	mu          sync.Mutex
}

// NewProfiler wraps the given detectors with timing instrumentation.
func NewProfiler(detectors []analyzer.Detector) (*Profiler, []analyzer.Detector) {
	p := &Profiler{start: time.Now()}
	runtime.GC() // clean slate for memory measurement
	runtime.ReadMemStats(&p.memBefore)

	timed := make([]*TimedDetector, len(detectors))
	instrumented := make([]analyzer.Detector, len(detectors))

	for i, d := range detectors {
		td := NewTimedDetector(d)
		timed[i] = td
		instrumented[i] = td
	}
	p.detectors = timed

	return p, instrumented
}

// RecordFile is called after each file is analyzed.
func (p *Profiler) RecordFile(filepath string, duration time.Duration, findings int) {
	p.mu.Lock()
	p.fileTimings = append(p.fileTimings, FileTiming{
		Filepath: filepath,
		Duration: duration,
		Findings: findings,
	})
	p.mu.Unlock()
}

// Finalize collects final memory stats and builds the ScanProfile.
func (p *Profiler) Finalize(filesAnalyzed, findingsFound int) *ScanProfile {
	var memAfter runtime.MemStats
	runtime.ReadMemStats(&memAfter)

	total := time.Since(p.start)

	detMap := make(map[string]*DetectorProfile, len(p.detectors))
	for _, td := range p.detectors {
		prof := td.Profile()
		profCopy := prof
		detMap[prof.Name] = &profCopy
	}

	prof := &ScanProfile{
		TotalDuration:   total,
		FilesAnalyzed:   filesAnalyzed,
		FindingsFound:   findingsFound,
		DetectorTimings: detMap,
		FileTimings:     p.slowestFiles(10),
		Memory: MemoryProfile{
			AllocBytes:     memAfter.TotalAlloc - p.memBefore.TotalAlloc,
			PeakHeapBytes:  memAfter.HeapSys,
			NumGC:          memAfter.NumGC - p.memBefore.NumGC,
			TotalAllocObjs: memAfter.Mallocs - p.memBefore.Mallocs,
		},
	}

	if total.Seconds() > 0 {
		prof.FilesPerSecond = float64(filesAnalyzed) / total.Seconds()
		prof.FindingsPerSecond = float64(findingsFound) / total.Seconds()
	}

	return prof
}

// slowestFiles returns the N files that took the most time to analyze.
func (p *Profiler) slowestFiles(n int) []FileTiming {
	p.mu.Lock()
	timings := make([]FileTiming, len(p.fileTimings))
	copy(timings, p.fileTimings)
	p.mu.Unlock()

	// Sort descending by duration
	for i := 0; i < len(timings); i++ {
		for j := i + 1; j < len(timings); j++ {
			if timings[j].Duration > timings[i].Duration {
				timings[i], timings[j] = timings[j], timings[i]
			}
		}
	}

	if n > len(timings) {
		n = len(timings)
	}
	return timings[:n]
}
