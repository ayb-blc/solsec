package detectors

import (
	"fmt"
	"strings"

	"github.com/ayb-blc/solsec/internal/analyzer"
	"github.com/ayb-blc/solsec/internal/callgraph"
	"github.com/ayb-blc/solsec/internal/parser"
	"github.com/ayb-blc/solsec/internal/symboltable"
)

// InterproceduralReentrancyDetector call graph kullanarak
//
//	function withdraw() external {
//	}
//
//	function _sendFunds() internal {
//	}
type InterproceduralReentrancyDetector struct{}

type stmtClass int

const (
	stmtExternalCall stmtClass = iota
	stmtInternalCall           // Internal call (transitive external call olabilir)
	stmtStateWrite             // State variable write
	stmtOther
)

func NewInterproceduralReentrancyDetector() *InterproceduralReentrancyDetector {
	return &InterproceduralReentrancyDetector{}
}

func (d *InterproceduralReentrancyDetector) Name() string { return "reentrancy-inter" }
func (d *InterproceduralReentrancyDetector) Severity() analyzer.Severity {
	return analyzer.Critical
}

func (d *InterproceduralReentrancyDetector) Analyze(
	cg *callgraph.CallGraph,
	table *symboltable.SymbolTable,
	filepath string,
) ([]analyzer.Finding, error) {

	var findings []analyzer.Finding

	for _, entry := range cg.EntryPoints {

		if !entry.TransitiveExternalCall {
			continue
		}

		if table.FunctionHasModifier(entry.Name, entry.Contract, "nonReentrant") {
			continue
		}

		// Call sequence analizi
		finding := d.analyzeCallSequence(entry, cg, table, filepath)
		if finding != nil {
			findings = append(findings, *finding)
		}
	}

	return findings, nil
}

// "Call sequence" nedir?
// Her statement ya:
//   - Internal call (o da sonunda external call yapabilir)
//   - State write
func (d *InterproceduralReentrancyDetector) analyzeCallSequence(
	entry *callgraph.FunctionNode,
	cg *callgraph.CallGraph,
	table *symboltable.SymbolTable,
	filepath string,
) *analyzer.Finding {

	if entry.ASTNode == nil || entry.ASTNode.FunctionDef == nil {
		return nil
	}

	fd := entry.ASTNode.FunctionDef
	if fd.Body == nil || fd.Body.Block == nil {
		return nil
	}

	statements := fd.Body.Block.Statements

	type classifiedStmt struct {
		class    stmtClass
		details  string
		calleeID callgraph.FunctionID
	}

	classified := make([]classifiedStmt, 0, len(statements))

	for _, stmt := range statements {
		class, details, calleeID := d.classifyStatement(stmt, entry, cg, table)
		classified = append(classified, classifiedStmt{class, details, calleeID})
	}

	firstDangerousIdx := -1
	dangerousDetails := ""
	var dangerousCallee *callgraph.FunctionNode

	for i, cs := range classified {
		if cs.class == stmtExternalCall {
			firstDangerousIdx = i
			dangerousDetails = cs.details
			break
		}
		if cs.class == stmtInternalCall {
			if calleeNode, ok := cg.Nodes[cs.calleeID]; ok {
				if calleeNode.TransitiveExternalCall {
					firstDangerousIdx = i
					dangerousDetails = fmt.Sprintf(
						"%s (calls %s which performs external call)",
						cs.details, cs.calleeID.Function(),
					)
					dangerousCallee = calleeNode
					break
				}
			}
		}
	}

	if firstDangerousIdx < 0 {
		return nil
	}

	stateWriteAfter := ""
	for i := firstDangerousIdx + 1; i < len(classified); i++ {
		if classified[i].class == stmtStateWrite {
			stateWriteAfter = classified[i].details
			break
		}
	}

	if stateWriteAfter == "" {
		return nil
	}

	callPath := d.buildCallPath(entry, dangerousCallee, cg)

	return &analyzer.Finding{
		DetectorName: d.Name(),
		Title: fmt.Sprintf(
			"Inter-procedural reentrancy: %s.%s",
			entry.Contract, entry.Name,
		),
		Description: fmt.Sprintf(
			"Function '%s.%s' is vulnerable to inter-procedural reentrancy.\n\n"+
				"Call chain that leads to external call:\n  %s\n\n"+
				"External interaction: %s\n"+
				"State update after interaction: %s\n\n"+
				"An attacker can re-enter the contract before the state is updated "+
				"by exploiting the external call in the call chain.",
			entry.Contract, entry.Name,
			callPath,
			dangerousDetails,
			stateWriteAfter,
		),
		Recommendation: fmt.Sprintf(
			"Option 1: Add 'nonReentrant' modifier to '%s'.\n"+
				"Option 2: Move state update ('%s') BEFORE the call to '%s'.\n"+
				"Option 3: Restructure so '%s' does not call functions that make external calls.",
			entry.Name, stateWriteAfter, dangerousDetails, entry.Name,
		),
		Filepath:   filepath,
		Severity:   analyzer.Critical,
		Confidence: analyzer.ConfidenceMedium, // Inter-procedural = daha fazla belirsizlik
		Tags:       []string{"reentrancy", "inter-procedural", "call-graph", "cei-violation"},
	}
}

func (d *InterproceduralReentrancyDetector) classifyStatement(
	_ *parser.ASTNode,
	_ *callgraph.FunctionNode,
	_ *callgraph.CallGraph,
	_ *symboltable.SymbolTable,
) (class stmtClass, details string, calleeID callgraph.FunctionID) {
	return stmtOther, "", ""
}

func (d *InterproceduralReentrancyDetector) buildCallPath(
	entry *callgraph.FunctionNode,
	dangerousCallee *callgraph.FunctionNode,
	cg *callgraph.CallGraph,
) string {
	if dangerousCallee == nil {
		return entry.Name + " → [external call]"
	}

	path := []string{entry.Name}
	// BFS ile entry'den dangerousCallee'ye giden yolu bul
	found := bfsPath(entry.ID, dangerousCallee.ID, cg)
	for _, id := range found {
		path = append(path, id.Function())
	}
	path = append(path, "[external call]")
	return strings.Join(path, " → ")
}

func bfsPath(from, to callgraph.FunctionID, cg *callgraph.CallGraph) []callgraph.FunctionID {
	type state struct {
		id   callgraph.FunctionID
		path []callgraph.FunctionID
	}

	visited := make(map[callgraph.FunctionID]bool)
	queue := []state{{from, nil}}

	for len(queue) > 0 {
		curr := queue[0]
		queue = queue[1:]

		if curr.id == to {
			return curr.path
		}
		if visited[curr.id] {
			continue
		}
		visited[curr.id] = true

		node, ok := cg.Nodes[curr.id]
		if !ok {
			continue
		}
		for _, cs := range node.Callees {
			if cs.IsResolved {
				newPath := append(append([]callgraph.FunctionID{}, curr.path...), cs.Callee)
				queue = append(queue, state{cs.Callee, newPath})
			}
		}
	}
	return nil
}
