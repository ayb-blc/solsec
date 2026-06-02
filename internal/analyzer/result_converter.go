package analyzer

import (
	"fmt"
	"strings"

	"github.com/ayb-blc/solsec/internal/callgraph"
	"github.com/ayb-blc/solsec/internal/taint"
)

// ToAnalysisResult converts an AdvancedResult into the reporter-facing result
// shape.
func (r *AdvancedResult) ToAnalysisResult() AnalysisResult {
	result := AnalysisResult{
		Filepath: r.Filepath,
	}

	for _, flow := range r.TaintFlows {
		result.Findings = append(result.Findings, taintFlowToFinding(flow))
	}

	for _, cycle := range r.SecurityCycles {
		result.Findings = append(result.Findings, cycleFindingToFinding(cycle, r.Filepath))
	}

	return result
}

func taintFlowToFinding(flow taint.TaintFlow) Finding {
	return Finding{
		DetectorName: "taint-analysis",
		Title:        fmt.Sprintf("Tainted %s reaches %s sink", flow.SourceLabel, flow.SinkKind),
		Description: fmt.Sprintf(
			"A value tainted by %s reaches a %s sink in %s.%s.",
			flow.SourceLabel,
			flow.SinkKind,
			flow.ContractName,
			flow.FunctionName,
		),
		Recommendation: "Validate or constrain tainted values before passing them to sensitive operations.",
		Severity:       High,
		Confidence:     ConfidenceMedium,
		Tags:           []string{"taint", flow.SourceLabel.String(), flow.SinkKind.String()},
	}
}

func cycleFindingToFinding(cycle callgraph.CycleFinding, filepath string) Finding {
	title := "Security-relevant call cycle"
	if len(cycle.Cycle) > 0 {
		parts := make([]string, len(cycle.Cycle))
		for i, fn := range cycle.Cycle {
			parts[i] = fn.String()
		}
		title = "Security-relevant call cycle: " + strings.Join(parts, " -> ")
	}
	return Finding{
		DetectorName:   "call-cycle",
		Title:          title,
		Description:    cycle.Risk,
		Recommendation: "Review the cycle for reentrancy, inconsistent state updates, and unexpected callback paths.",
		Filepath:       filepath,
		Severity:       High,
		Confidence:     ConfidenceMedium,
		Tags:           []string{"call-graph", "cycle"},
	}
}

// MultiFileResult groups analysis output across multiple files.
type MultiFileResult struct {
	Results       []AnalysisResult
	CallGraph     interface{} // *callgraph.CrossContractCallGraph
	TaintFlows    []interface{}
	FilesAnalyzed int
	Errors        []FileError
}

type FileError struct {
	Filepath string
	Err      error
}

// Findings returns all findings as a flat list.
func (m *MultiFileResult) Findings() []Finding {
	var all []Finding
	for _, r := range m.Results {
		all = append(all, r.Findings...)
	}
	return all
}

// FindingsBySeverity groups findings by severity.
func (m *MultiFileResult) FindingsBySeverity() map[Severity][]Finding {
	grouped := make(map[Severity][]Finding)
	for _, f := range m.Findings() {
		grouped[f.Severity] = append(grouped[f.Severity], f)
	}
	return grouped
}
