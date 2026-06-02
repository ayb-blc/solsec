package baseline

import (
	"github.com/ayb-blc/solsec/internal/analyzer"
	"github.com/ayb-blc/solsec/internal/fingerprint"
)

type DiffResult struct {
	New []analyzer.Finding

	Existing []analyzer.Finding

	Resolved []BaselineFinding
}

func (d *DiffResult) HasNewFindings() bool {
	return len(d.New) > 0
}

func (d *DiffResult) NewBySeverity() map[analyzer.Severity][]analyzer.Finding {
	groups := make(map[analyzer.Severity][]analyzer.Finding)
	for _, f := range d.New {
		groups[f.Severity] = append(groups[f.Severity], f)
	}
	return groups
}

func Diff(
	results []analyzer.AnalysisResult,
	baseline *Baseline,
	projectRoot string,
) *DiffResult {
	diff := &DiffResult{}

	currentIDs := make(map[string]bool)

	for _, result := range results {
		for _, f := range result.Findings {
			fp := fingerprint.Compute(f, projectRoot)
			// Finding'e fingerprint ID'sini ekle
			f.FingerprintID = fp.ID
			currentIDs[fp.ID] = true

			if baseline.Contains(fp.ID) {
				diff.Existing = append(diff.Existing, f)
			} else {
				diff.New = append(diff.New, f)
			}
		}
	}

	for id, bf := range baseline.Findings {
		if !currentIDs[id] {
			diff.Resolved = append(diff.Resolved, bf)
		}
	}

	return diff
}

func (d *DiffResult) FilterAboveThreshold(threshold analyzer.Severity) []analyzer.Finding {
	var above []analyzer.Finding
	for _, f := range d.New {
		if f.Severity >= threshold {
			above = append(above, f)
		}
	}
	return above
}
