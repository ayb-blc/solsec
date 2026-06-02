package integration_test

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ayb-blc/solsec/internal/analyzer"
	"github.com/ayb-blc/solsec/internal/callgraph"
	"github.com/ayb-blc/solsec/internal/detectors"
	"github.com/ayb-blc/solsec/internal/parser"
	"github.com/ayb-blc/solsec/internal/symboltable"
	"github.com/ayb-blc/solsec/internal/taint"
)

func TestFullPipeline(t *testing.T) {
	if !solcAvailable() {
		t.Skip("solc not available — skipping integration test")
	}

	contractPath := testContractPath(t, "vulnerable/reentrancy/basic.sol")

	runner := parser.NewSolcRunner("")
	unit, err := runner.ParseFile(contractPath)
	if err != nil {
		t.Fatalf("AST parse failed: %v", err)
	}
	if unit == nil {
		t.Fatal("nil AST returned")
	}

	content, _ := os.ReadFile(contractPath)
	srcMap := parser.NewSourceMap(string(content))

	symTable, err := symboltable.Build(unit, srcMap)
	if err != nil {
		t.Fatalf("symbol table build failed: %v", err)
	}

	stateVars := symTable.StateVariablesWrittenAfterCall()
	t.Logf("State variables written after call: %d", len(stateVars))

	cg, err := callgraph.Build(unit, symTable)
	if err != nil {
		t.Fatalf("call graph build failed: %v", err)
	}

	withdrawID := callgraph.NewFunctionID("BasicReentrancy", "withdraw")
	withdrawNode, ok := cg.Nodes[withdrawID]
	if !ok {
		t.Fatal("withdraw function not found in call graph")
	}

	if !withdrawNode.HasExternalCall && !withdrawNode.TransitiveExternalCall {
		t.Error("withdraw() should have external call flagged")
	}

	engine := taint.NewEngine(symTable, unit)
	flows := engine.Analyze()
	t.Logf("Taint flows found: %d", len(flows))

	reentrancyDet := detectors.NewReentrancyASTDetector()
	findings, err := reentrancyDet.AnalyzeAST(unit, contractPath, srcMap)
	if err != nil {
		t.Fatalf("detector failed: %v", err)
	}

	if len(findings) == 0 {
		t.Error("expected at least 1 reentrancy finding in basic.sol")
	}

	for _, f := range findings {
		t.Logf("Finding: [%s] %s at line %d", f.Severity, f.Title, f.Line)

		if f.Title == "" {
			t.Error("finding has empty title")
		}
		if f.Description == "" {
			t.Error("finding has empty description")
		}
		if f.Recommendation == "" {
			t.Error("finding has empty recommendation")
		}
		if f.Severity < analyzer.Low {
			t.Errorf("finding has invalid severity: %v", f.Severity)
		}
	}
}

func TestPipelineWithSafeContract(t *testing.T) {
	if !solcAvailable() {
		t.Skip("solc not available")
	}

	contractPath := testContractPath(t, "safe/reentrancy/with_guard.sol")

	runner := parser.NewSolcRunner("")
	unit, err := runner.ParseFile(contractPath)
	if err != nil {
		t.Fatalf("AST parse failed: %v", err)
	}

	content, _ := os.ReadFile(contractPath)
	srcMap := parser.NewSourceMap(string(content))
	if _, err := symboltable.Build(unit, srcMap); err != nil {
		t.Fatalf("symbol table build failed: %v", err)
	}

	det := detectors.NewReentrancyASTDetector()
	findings, err := det.AnalyzeAST(unit, contractPath, srcMap)
	if err != nil {
		t.Fatalf("detector failed: %v", err)
	}

	if len(findings) > 0 {
		t.Errorf("false positive: %d findings in safe contract\n%s",
			len(findings), formatFindings(findings))
	}
}

func TestSymbolTableAccuracy(t *testing.T) {
	if !solcAvailable() {
		t.Skip("solc not available")
	}

	source := `
pragma solidity ^0.8.0;
contract ShadowTest {
    uint256 public balance = 100;  // state variable

    function test(uint256 balance) external returns (uint256) {
        return balance * 2;  // state'e dokunmuyor
    }
}`

	tmpFile := writeTempContract(t, source)
	defer os.Remove(tmpFile)

	runner := parser.NewSolcRunner("")
	unit, err := runner.ParseFile(tmpFile)
	if err != nil {
		t.Skipf("solc parse failed (expected in some envs): %v", err)
	}

	srcMap := parser.NewSourceMap(source)
	symTable, err := symboltable.Build(unit, srcMap)
	if err != nil {
		t.Fatalf("symbol table failed: %v", err)
	}

	stateVars := symTable.StateVariablesWrittenAfterCall()
	if len(stateVars) > 0 {
		t.Errorf("false positive: parameter 'balance' misidentified as state variable write after call")
	}
}

func solcAvailable() bool {
	runner := parser.NewSolcRunner("")
	return runner.IsAvailable()
}

func testContractPath(t *testing.T, relative string) string {
	t.Helper()
	_, filename, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(filename), "..", "..")
	return filepath.Join(root, "testdata", "contracts", relative)
}

func writeTempContract(t *testing.T, source string) string {
	t.Helper()
	f, err := os.CreateTemp("", "solsec_test_*.sol")
	if err != nil {
		t.Fatalf("cannot create temp file: %v", err)
	}
	if _, err := f.WriteString(source); err != nil {
		t.Fatalf("cannot write temp file: %v", err)
	}
	f.Close()
	return f.Name()
}

func formatFindings(findings []analyzer.Finding) string {
	var sb strings.Builder
	for _, f := range findings {
		fmt.Fprintf(&sb, "\n  [%s] %s (line %d, detector: %s)",
			f.Severity, f.Title, f.Line, f.DetectorName)
	}
	return sb.String()
}
