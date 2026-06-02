package analyzer

import (
	"fmt"

	"github.com/ayb-blc/solsec/internal/rules"
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
}

func (f Finding) String() string {
	return fmt.Sprintf("[%s] %s at %s:%d", f.Severity, f.Title, f.Filepath, f.Line)
}
