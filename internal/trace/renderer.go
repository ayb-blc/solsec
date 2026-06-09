// internal/trace/renderer.go

package trace

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ─── Text Renderer ────────────────────────────────────────────────────────────

// RenderText formats a Trace for terminal output.
// Produces a tree-style evidence chain with box-drawing characters.
//
// Output example:
//
//	📍 Evidence chain:
//	  ┌ Vault.sol:41  READ   balances[msg.sender]       require check
//	  ├ Vault.sol:43  CALL   msg.sender.call()           ← external call
//	  └ Vault.sol:44  WRITE  balances[msg.sender] -= x   ← ❌ write after call
func RenderText(t *Trace, useColor bool) string {
	if t == nil || t.IsEmpty() {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("    📍 Evidence chain:\n")

	for i, step := range t.Steps {
		// Tree connector
		connector := "  ├ "
		if i == len(t.Steps)-1 {
			connector = "  └ "
		} else if i == 0 {
			connector = "  ┌ "
		}

		// Location column (fixed width 20)
		locStr := step.Location.String()
		if locStr == "" {
			locStr = "(inferred)"
		}
		locPadded := fmt.Sprintf("%-22s", locStr)

		// Kind label (fixed width 8)
		kindLabel := fmt.Sprintf("%-8s", step.Kind.label())

		// Detail
		detail := step.Detail
		if len(detail) > 40 {
			detail = detail[:37] + "..."
		}
		detailPadded := fmt.Sprintf("%-42s", detail)

		// Note / issue marker
		note := step.Note
		if step.IsIssue {
			if useColor {
				note = "\033[31m← ❌ " + note + "\033[0m"
			} else {
				note = "← ❌ " + note
			}
		} else if note != "" {
			note = "  " + note
		}

		sb.WriteString(fmt.Sprintf(
			"    %s%s  %s  %s  %s\n",
			connector, locPadded, kindLabel, detailPadded, note,
		))
	}

	return sb.String()
}

// ─── JSON Renderer ────────────────────────────────────────────────────────────

// JSONTrace is the wire format for a trace in JSON output.
type JSONTrace struct {
	Summary string     `json:"summary"`
	Steps   []JSONStep `json:"steps"`
}

type JSONStep struct {
	Kind     string `json:"kind"`
	Detail   string `json:"detail"`
	Filepath string `json:"file,omitempty"`
	Line     int    `json:"line,omitempty"`
	Snippet  string `json:"snippet,omitempty"`
	Note     string `json:"note,omitempty"`
	IsIssue  bool   `json:"is_issue,omitempty"`
}

// ToJSON converts a Trace to its JSON representation.
func ToJSON(t *Trace) *JSONTrace {
	if t == nil {
		return nil
	}
	jt := &JSONTrace{Summary: t.Summary}
	for _, step := range t.Steps {
		jt.Steps = append(jt.Steps, JSONStep{
			Kind:     step.Kind.label(),
			Detail:   step.Detail,
			Filepath: step.Location.Filepath,
			Line:     step.Location.Line,
			Snippet:  step.Location.Snippet,
			Note:     step.Note,
			IsIssue:  step.IsIssue,
		})
	}
	return jt
}

// MarshalJSON marshals a Trace to JSON bytes.
func MarshalJSON(t *Trace) ([]byte, error) {
	return json.Marshal(ToJSON(t))
}

// ─── SARIF codeFlows Renderer ─────────────────────────────────────────────────

// SARIFCodeFlow is a SARIF 2.1.0 codeFlow element.
// https://docs.oasis-open.org/sarif/sarif/v2.1.0/csprd01/sarif-v2.1.0-csprd01.html#_Toc10540924
type SARIFCodeFlow struct {
	ThreadFlows []SARIFThreadFlow `json:"threadFlows"`
}

type SARIFThreadFlow struct {
	Locations []SARIFThreadFlowLocation `json:"locations"`
}

type SARIFThreadFlowLocation struct {
	Location   SARIFLocation          `json:"location"`
	State      map[string]interface{} `json:"state,omitempty"`
	Importance string                 `json:"importance,omitempty"` // essential | important | unimportant
}

type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
	Message          *SARIFMessage         `json:"message,omitempty"`
}

type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           SARIFRegion           `json:"region,omitempty"`
}

type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

type SARIFRegion struct {
	StartLine int `json:"startLine,omitempty"`
}

type SARIFMessage struct {
	Text string `json:"text"`
}

// ToSARIFCodeFlow converts a Trace to a SARIF codeFlow element.
// The resulting codeFlow can be embedded in a SARIF result.
func ToSARIFCodeFlow(t *Trace) *SARIFCodeFlow {
	if t == nil || t.IsEmpty() {
		return nil
	}

	flow := &SARIFCodeFlow{}
	thread := SARIFThreadFlow{}

	for _, step := range t.Steps {
		importance := "important"
		if step.IsIssue {
			importance = "essential"
		} else if step.Kind == KindInfo || step.Kind == KindEffect {
			importance = "unimportant"
		}

		msg := step.Kind.label() + ": " + step.Detail
		if step.Note != "" {
			msg += " — " + step.Note
		}

		loc := SARIFThreadFlowLocation{
			Importance: importance,
			Location: SARIFLocation{
				PhysicalLocation: SARIFPhysicalLocation{
					ArtifactLocation: SARIFArtifactLocation{
						URI: step.Location.Filepath,
					},
					Region: SARIFRegion{StartLine: step.Location.Line},
				},
				Message: &SARIFMessage{Text: msg},
			},
		}
		thread.Locations = append(thread.Locations, loc)
	}

	flow.ThreadFlows = []SARIFThreadFlow{thread}
	return flow
}
