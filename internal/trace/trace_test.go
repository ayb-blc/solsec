// internal/trace/trace_test.go

package trace_test

import (
	"strings"
	"testing"

	"github.com/ayb-blc/solsec/internal/trace"
)

func TestBuilder_FluentAPI(t *testing.T) {
	tr := trace.NewBuilder("test trace").
		Read("balances[msg.sender]",
			trace.Location{Filepath: "Vault.sol", Line: 41, Snippet: "require(balances[msg.sender] >= amount)"},
			"check").
		CallIssue("msg.sender.call()",
			trace.Location{Filepath: "Vault.sol", Line: 43, Snippet: `(bool ok,) = msg.sender.call{value: x}("")`},
			"external call").
		WriteIssue("balances[msg.sender]",
			trace.Location{Filepath: "Vault.sol", Line: 44, Snippet: "balances[msg.sender] -= amount"},
			"write after call").
		Build()

	if tr.Len() != 3 {
		t.Errorf("steps = %d, want 3", tr.Len())
	}
	issue := tr.IssueStep()
	if issue == nil {
		t.Fatal("IssueStep = nil, want the write step")
	}
	if issue.Kind != trace.KindWrite {
		t.Errorf("issue kind = %v, want KindWrite", issue.Kind)
	}
}

func TestRenderText_ContainsKeyInfo(t *testing.T) {
	tr := trace.NewBuilder("CEI violation").
		Read("balances[msg.sender]",
			trace.Location{Filepath: "Vault.sol", Line: 41}, "check").
		CallIssue("msg.sender.call()",
			trace.Location{Filepath: "Vault.sol", Line: 43}, "external call").
		WriteIssue("balances[msg.sender]",
			trace.Location{Filepath: "Vault.sol", Line: 44}, "write after call").
		Build()

	text := trace.RenderText(tr, false)

	mustContain := []string{
		"Evidence chain",
		"READ",
		"CALL",
		"WRITE",
		"Vault.sol:41",
		"Vault.sol:43",
		"Vault.sol:44",
		"❌",
	}
	for _, s := range mustContain {
		if !strings.Contains(text, s) {
			t.Errorf("rendered text missing %q\n\nGot:\n%s", s, text)
		}
	}
}

func TestToJSON_Structure(t *testing.T) {
	tr := trace.NewBuilder("test").
		Write("owner", trace.Location{Filepath: "T.sol", Line: 10}, "privileged write").
		Missing("onlyOwner", trace.Location{Filepath: "T.sol"}, "no protection").
		Build()

	jt := trace.ToJSON(tr)

	if jt == nil {
		t.Fatal("ToJSON returned nil")
	}
	if len(jt.Steps) != 2 {
		t.Errorf("json steps = %d, want 2", len(jt.Steps))
	}
	if jt.Steps[1].Kind != "MISSING" {
		t.Errorf("step[1].kind = %q, want MISSING", jt.Steps[1].Kind)
	}
	if !jt.Steps[1].IsIssue {
		t.Error("MISSING step should be marked is_issue")
	}
}

func TestToSARIFCodeFlow_ThreadFlowLocations(t *testing.T) {
	tr := trace.NewBuilder("override regression").
		Override("Base.pause() [onlyOwner]",
			trace.Location{Filepath: "Base.sol", Line: 15}, "root definition").
		OverrideIssue("Child.pause() (none)",
			trace.Location{Filepath: "Child.sol", Line: 42}, "modifier dropped").
		Build()

	cf := trace.ToSARIFCodeFlow(tr)

	if cf == nil {
		t.Fatal("ToSARIFCodeFlow returned nil")
	}
	if len(cf.ThreadFlows) != 1 {
		t.Fatalf("thread flows = %d, want 1", len(cf.ThreadFlows))
	}
	locs := cf.ThreadFlows[0].Locations
	if len(locs) != 2 {
		t.Fatalf("locations = %d, want 2", len(locs))
	}

	// Root definition — important
	if locs[0].Importance != "important" {
		t.Errorf("root importance = %q, want important", locs[0].Importance)
	}
	// Issue step — essential
	if locs[1].Importance != "essential" {
		t.Errorf("issue importance = %q, want essential", locs[1].Importance)
	}
	if locs[1].Location.PhysicalLocation.Region.StartLine != 42 {
		t.Errorf("issue line = %d, want 42",
			locs[1].Location.PhysicalLocation.Region.StartLine)
	}
}

func TestNilTrace_SafeRender(t *testing.T) {
	// nil trace should never panic
	text := trace.RenderText(nil, false)
	if text != "" {
		t.Errorf("nil trace rendered %q, want empty string", text)
	}
	jt := trace.ToJSON(nil)
	if jt != nil {
		t.Error("ToJSON(nil) should return nil")
	}
	cf := trace.ToSARIFCodeFlow(nil)
	if cf != nil {
		t.Error("ToSARIFCodeFlow(nil) should return nil")
	}
}

func TestEmptyTrace_SafeRender(t *testing.T) {
	tr := trace.NewBuilder("").Build()
	text := trace.RenderText(tr, false)
	if text != "" {
		t.Errorf("empty trace rendered non-empty: %q", text)
	}
}
