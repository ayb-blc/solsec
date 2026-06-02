package reporter

import (
	"github.com/ayb-blc/solsec/internal/analyzer"
)

// Reporter renders analysis results in a specific output format.
type Reporter interface {
	Report(results []analyzer.AnalysisResult) error
}

// SummaryStats stores aggregate statistics for one analysis run.
type SummaryStats struct {
	TotalFiles    int
	FilesWithBugs int
	TotalFindings int
	BySeverity    map[analyzer.Severity]int
	ByDetector    map[string]int
	ByConfidence  map[analyzer.Confidence]int
}

func ComputeStats(results []analyzer.AnalysisResult) SummaryStats {
	stats := SummaryStats{
		TotalFiles:   len(results),
		BySeverity:   make(map[analyzer.Severity]int),
		ByDetector:   make(map[string]int),
		ByConfidence: make(map[analyzer.Confidence]int),
	}

	for _, result := range results {
		if len(result.Findings) > 0 {
			stats.FilesWithBugs++
		}
		for _, f := range result.Findings {
			stats.TotalFindings++
			stats.BySeverity[f.Severity]++
			stats.ByDetector[f.DetectorName]++
			stats.ByConfidence[f.Confidence]++
		}
	}

	return stats
}

// HasAnalysisErrors reports whether the analyzer failed to read or process at
// least one target file. Findings are security results; analysis errors mean
// the scan was incomplete and CI should treat that differently.
func HasAnalysisErrors(results []analyzer.AnalysisResult) bool {
	for _, result := range results {
		if result.Error != nil {
			return true
		}
	}
	return false
}

// Convention:
func ExitCode(stats SummaryStats, failOn analyzer.Severity) int {
	for sev := analyzer.Critical; sev >= failOn; sev-- {
		if stats.BySeverity[sev] > 0 {
			return 1
		}
	}
	return 0
}
