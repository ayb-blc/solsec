// internal/trace/trace.go

package trace

import (
	"fmt"
	"strings"
)

// StepKind categorises each piece of evidence in a trace.
type StepKind uint8

const (
	KindRead         StepKind = iota // state variable read
	KindWrite                        // state variable write
	KindExternalCall                 // call to external address
	KindInternalCall                 // call to internal function
	KindInherits                     // contract A is B
	KindOverride                     // function override in child
	KindModifier                     // modifier applied to function
	KindMissing                      // something absent that should be present
	KindEffect                       // downstream consequence
	KindInfo                         // neutral annotation
)

func (k StepKind) label() string {
	switch k {
	case KindRead:
		return "READ"
	case KindWrite:
		return "WRITE"
	case KindExternalCall:
		return "CALL"
	case KindInternalCall:
		return "CALL (internal)"
	case KindInherits:
		return "INHERITS"
	case KindOverride:
		return "OVERRIDE"
	case KindModifier:
		return "MODIFIER"
	case KindMissing:
		return "MISSING"
	case KindEffect:
		return "EFFECT"
	default:
		return "INFO"
	}
}

// Location identifies a specific source position.
type Location struct {
	Filepath string
	Line     int
	Snippet  string // trimmed source line content
}

func (l Location) String() string {
	if l.Line == 0 {
		return shortPath(l.Filepath)
	}
	return fmt.Sprintf("%s:%d", shortPath(l.Filepath), l.Line)
}

// Step is one piece of evidence in the reasoning chain.
type Step struct {
	Kind     StepKind
	Detail   string // what: "balances[msg.sender]", "onlyOwner", etc.
	Location Location
	Note     string // why this step matters
	IsIssue  bool   // true for the problematic step
}

// Trace is the ordered sequence of evidence that led to a finding.
type Trace struct {
	// Steps from earliest to latest (root cause → symptom).
	Steps []Step

	// Summary is a one-line description of the full reasoning.
	Summary string
}

// Len returns the number of steps in the trace.
func (t *Trace) Len() int { return len(t.Steps) }

// IsEmpty reports whether the trace has no steps.
func (t *Trace) IsEmpty() bool { return len(t.Steps) == 0 }

// IssueStep returns the last step marked IsIssue, or nil. When a trace marks
// more than one step, the last issue is the primary failing consequence.
func (t *Trace) IssueStep() *Step {
	for i := len(t.Steps) - 1; i >= 0; i-- {
		if t.Steps[i].IsIssue {
			return &t.Steps[i]
		}
	}
	return nil
}

// shortPath trims the path to the last two components for readability.
func shortPath(p string) string {
	parts := strings.Split(strings.ReplaceAll(p, "\\", "/"), "/")
	if len(parts) <= 2 {
		return p
	}
	return "..." + "/" + strings.Join(parts[len(parts)-2:], "/")
}
