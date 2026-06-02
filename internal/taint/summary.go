package taint

import (
	"github.com/ayb-blc/solsec/internal/callgraph"
	"github.com/ayb-blc/solsec/internal/parser"
	"github.com/ayb-blc/solsec/internal/symboltable"
)

type FunctionSummary struct {
	FunctionID callgraph.FunctionID

	ParameterFlows []ParameterFlow

	ReturnTaintedBy []int

	StateWriteByParam map[int][]string

	AlwaysSinks bool

	Computed bool
}

type ParameterFlow struct {
	ParamIndex int
	ParamName  string

	ReachesReturn bool

	ReachesSinks []SinkKind

	ReachesStateWrite bool

	PropagatesTo []calleeParam
}

type calleeParam struct {
	CalleeID   callgraph.FunctionID
	ParamIndex int
}

// SummaryBuilder computes per-function summaries using callee summaries.
type SummaryBuilder struct {
	cg        *callgraph.CallGraph
	table     *symboltable.SymbolTable
	summaries map[callgraph.FunctionID]*FunctionSummary

	inProgress map[callgraph.FunctionID]bool
}

func NewSummaryBuilder(
	cg *callgraph.CallGraph,
	table *symboltable.SymbolTable,
) *SummaryBuilder {
	return &SummaryBuilder{
		cg:         cg,
		table:      table,
		summaries:  make(map[callgraph.FunctionID]*FunctionSummary),
		inProgress: make(map[callgraph.FunctionID]bool),
	}
}

func (sb *SummaryBuilder) BuildAll() map[callgraph.FunctionID]*FunctionSummary {
	for id := range sb.cg.Nodes {
		sb.buildSummary(id)
	}
	return sb.summaries
}

// buildSummary computes the summary for one function.
func (sb *SummaryBuilder) buildSummary(id callgraph.FunctionID) *FunctionSummary {
	if s, ok := sb.summaries[id]; ok && s.Computed {
		return s
	}

	if sb.inProgress[id] {
		return sb.conservativeSummary(id)
	}

	sb.inProgress[id] = true
	defer func() { sb.inProgress[id] = false }()

	node, ok := sb.cg.Nodes[id]
	if !ok {
		return sb.conservativeSummary(id)
	}

	for _, cs := range node.Callees {
		if cs.IsResolved {
			sb.buildSummary(cs.Callee)
		}
	}

	summary := sb.computeFunctionSummary(id, node)
	sb.summaries[id] = summary
	return summary
}

// computeFunctionSummary computes a function summary from local symbols and callee summaries.
func (sb *SummaryBuilder) computeFunctionSummary(
	id callgraph.FunctionID,
	node *callgraph.FunctionNode,
) *FunctionSummary {

	summary := &FunctionSummary{
		FunctionID:        id,
		StateWriteByParam: make(map[int][]string),
		Computed:          true,
	}

	if node.ASTNode == nil || node.ASTNode.FunctionDef == nil {
		return summary
	}

	fd := node.ASTNode.FunctionDef

	// Parametreleri al
	params := extractParams(fd)
	summary.ParameterFlows = make([]ParameterFlow, len(params))
	for i, p := range params {
		summary.ParameterFlows[i] = ParameterFlow{
			ParamIndex: i,
			ParamName:  p.name,
		}
	}

	fnID := string(id)
	_ = fnID

	for i := range params {
		flow := &summary.ParameterFlows[i]

		flow.ReachesReturn = sb.paramReachesReturn(i, node)

		flow.ReachesSinks = sb.paramReachesSinks(i, node)

		stateVars := sb.paramReachesStateWrite(i, node)
		if len(stateVars) > 0 {
			flow.ReachesStateWrite = true
			summary.StateWriteByParam[i] = stateVars
		}

		flow.PropagatesTo = sb.findCalleesPropagation(i, node)
	}

	summary.AlwaysSinks = node.HasExternalCall || node.TransitiveExternalCall

	return summary
}

func (sb *SummaryBuilder) paramReachesReturn(
	paramIdx int,
	node *callgraph.FunctionNode,
) bool {
	if node.ASTNode == nil || node.ASTNode.FunctionDef == nil {
		return false
	}

	fd := node.ASTNode.FunctionDef
	params := extractParams(fd)
	if paramIdx >= len(params) {
		return false
	}

	paramName := params[paramIdx].name

	if fd.Body == nil || fd.Body.Block == nil {
		return false
	}

	for _, stmt := range fd.Body.Block.Statements {
		if stmt.NodeType == "Return" && stmt.ReturnStmt != nil {
			if containsIdentifier(stmt.ReturnStmt.Expression, paramName) {
				return true
			}
		}
	}

	for _, cs := range node.Callees {
		if !cs.IsResolved {
			continue
		}
		calleeSummary, ok := sb.summaries[cs.Callee]
		if !ok {
			continue
		}

		calleeParamIdx := sb.findParamPositionInCall(paramName, cs)
		if calleeParamIdx < 0 {
			continue
		}

		// Check whether the callee returns this parameter.
		if calleeParamIdx < len(calleeSummary.ParameterFlows) &&
			calleeSummary.ParameterFlows[calleeParamIdx].ReachesReturn {
			return true
		}
	}

	return false
}

func (sb *SummaryBuilder) paramReachesSinks(
	paramIdx int,
	node *callgraph.FunctionNode,
) []SinkKind {

	var sinks []SinkKind

	if node.ASTNode == nil || node.ASTNode.FunctionDef == nil {
		return sinks
	}

	fd := node.ASTNode.FunctionDef
	params := extractParams(fd)
	if paramIdx >= len(params) {
		return sinks
	}

	paramName := params[paramIdx].name

	for _, cs := range node.Callees {
		switch cs.Kind {
		case callgraph.CallExternal:
			for _, argNode := range cs.ArgumentNodes {
				if containsIdentifier(argNode, paramName) {
					sinks = append(sinks, SinkExternalCall)
					break
				}
			}
		case callgraph.CallDelegatecall:
			for _, argNode := range cs.ArgumentNodes {
				if containsIdentifier(argNode, paramName) {
					sinks = append(sinks, SinkDelegatecall)
					break
				}
			}
		}

		if cs.IsResolved {
			calleeSummary, ok := sb.summaries[cs.Callee]
			if !ok {
				continue
			}
			calleeParamIdx := sb.findParamPositionInCall(paramName, cs)
			if calleeParamIdx >= 0 &&
				calleeParamIdx < len(calleeSummary.ParameterFlows) {
				sinks = append(sinks,
					calleeSummary.ParameterFlows[calleeParamIdx].ReachesSinks...,
				)
			}
		}
	}

	return dedupSinks(sinks)
}

func (sb *SummaryBuilder) paramReachesStateWrite(
	paramIdx int,
	node *callgraph.FunctionNode,
) []string {

	params := extractParams(node.ASTNode.FunctionDef)
	if paramIdx >= len(params) {
		return nil
	}
	paramName := params[paramIdx].name

	var stateVars []string
	for _, sym := range sb.table.AllSymbols {
		if !sym.IsStateVariable() {
			continue
		}
		for _, write := range sym.Writes {
			if write.InFunction == node.Name {
				if write.Node == nil || containsIdentifier(write.Node, paramName) {
					stateVars = append(stateVars, sym.Name)
					break
				}
			}
		}
	}
	return stateVars
}

func (sb *SummaryBuilder) findParamPositionInCall(
	paramName string,
	cs *callgraph.CallSite,
) int {
	for i, argNode := range cs.ArgumentNodes {
		if containsIdentifier(argNode, paramName) {
			return i
		}
	}
	return -1
}

func (sb *SummaryBuilder) findCalleesPropagation(
	paramIdx int,
	node *callgraph.FunctionNode,
) []calleeParam {

	params := extractParams(node.ASTNode.FunctionDef)
	if paramIdx >= len(params) {
		return nil
	}
	paramName := params[paramIdx].name

	var result []calleeParam
	for _, cs := range node.Callees {
		if !cs.IsResolved {
			continue
		}
		pos := sb.findParamPositionInCall(paramName, cs)
		if pos >= 0 {
			result = append(result, calleeParam{
				CalleeID:   cs.Callee,
				ParamIndex: pos,
			})
		}
	}
	return result
}

func (sb *SummaryBuilder) conservativeSummary(id callgraph.FunctionID) *FunctionSummary {
	return &FunctionSummary{
		FunctionID:  id,
		AlwaysSinks: true,
		Computed:    true,
	}
}

type paramInfo struct {
	name     string
	typeName string
	index    int
}

func extractParams(fd *parser.FunctionDefinition) []paramInfo {
	if fd == nil || fd.Parameters == nil {
		return nil
	}
	params := make([]paramInfo, len(fd.Parameters.Parameters))
	for i, p := range fd.Parameters.Parameters {
		params[i] = paramInfo{
			name:  p.Name,
			index: i,
		}
	}
	return params
}

func containsIdentifier(node *parser.ASTNode, name string) bool {
	if node == nil {
		return false
	}
	switch node.NodeType {
	case "Identifier":
		return node.Identifier != nil && node.Identifier.Name == name
	case "MemberAccess":
		if node.MemberAccess != nil {
			return containsIdentifier(node.MemberAccess.Expression, name)
		}
	case "BinaryOperation":
		if node.BinaryOp != nil {
			return containsIdentifier(node.BinaryOp.LeftExpression, name) ||
				containsIdentifier(node.BinaryOp.RightExpression, name)
		}
	case "FunctionCall":
		if node.FunctionCall != nil {
			for _, arg := range node.FunctionCall.Arguments {
				if containsIdentifier(arg, name) {
					return true
				}
			}
		}
	case "IndexAccess":
		if node.IndexAccess != nil {
			return containsIdentifier(node.IndexAccess.BaseExpression, name) ||
				containsIdentifier(node.IndexAccess.IndexExpression, name)
		}
	}
	return false
}

func dedupSinks(sinks []SinkKind) []SinkKind {
	seen := make(map[SinkKind]bool)
	var result []SinkKind
	for _, s := range sinks {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}
