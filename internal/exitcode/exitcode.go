package exitcode

import (
	"github.com/ayb-blc/solsec/internal/analyzer"
	"github.com/ayb-blc/solsec/internal/baseline"
)

const (
	Success       = 0
	Finding       = 1
	AnalysisError = 2
	UsageError    = 3
)

func FromResults(
	results []analyzer.AnalysisResult,
	threshold analyzer.Severity,
) int {
	hasError := false
	for _, r := range results {
		if r.Error != nil {
			hasError = true
		}
		for _, f := range r.Findings {
			if f.Severity >= threshold {
				return Finding
			}
		}
	}

	if hasError {
		return AnalysisError
	}
	return Success
}

func FromDiff(
	diff *baseline.DiffResult,
	threshold analyzer.Severity,
) int {
	above := diff.FilterAboveThreshold(threshold)
	if len(above) > 0 {
		return Finding
	}
	return Success
}

func FromError(err error) int {
	if err == nil {
		return Success
	}
	return AnalysisError
}

func Description(code int) string {
	switch code {
	case Success:
		return "No findings above threshold"
	case Finding:
		return "Findings above threshold detected"
	case AnalysisError:
		return "Analysis error occurred"
	case UsageError:
		return "Invalid usage or configuration"
	default:
		return "Unknown exit code"
	}
}
