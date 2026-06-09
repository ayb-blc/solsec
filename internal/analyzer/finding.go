package analyzer

import (
	"fmt"

	"github.com/ayb-blc/solsec/internal/rules"
	"github.com/ayb-blc/solsec/internal/trace"
)

// Finding is the reporter-facing representation of one security issue.
type Finding struct {
	// RuleID stable product rule identifier.
	// DetectorName remains for backward compatibility and internal grouping.
	RuleID rules.RuleID

	// FingerprintID is a deterministic finding identity used by baseline mode.
	FingerprintID string

	// Rule is optional enriched metadata resolved from RuleID by reporters.
	Rule *rules.Rule

	DetectorName string

	Title string

	Description string

	Recommendation string

	Filepath string

	Line int

	CodeSnippet string

	Severity Severity

	Confidence Confidence

	Tags []string

	// Trace is the evidence chain that led to this finding. It is populated by
	// graph-aware detectors and may be nil for detectors that still use the
	// legacy single-file analysis path.
	Trace *trace.Trace
}

func (f Finding) String() string {
	return fmt.Sprintf("[%s] %s at %s:%d", f.Severity, f.Title, f.Filepath, f.Line)
}

// WithTrace attaches an evidence trace to the finding.
func (f Finding) WithTrace(t *trace.Trace) Finding {
	f.Trace = t
	return f
}
