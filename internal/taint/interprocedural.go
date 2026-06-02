package taint

import (
	"github.com/ayb-blc/solsec/internal/callgraph"
	"github.com/ayb-blc/solsec/internal/parser"
	"github.com/ayb-blc/solsec/internal/symboltable"
)

type InterproceduralEngine struct {
	cg        *callgraph.CallGraph
	table     *symboltable.SymbolTable
	unit      *parser.SourceUnit
	summaries map[callgraph.FunctionID]*FunctionSummary

	// Context-sensitive taint state:
	taintState map[callgraph.FunctionID]*functionTaintState

	flows []TaintFlow
}

type functionTaintState struct {
	TaintedParams uint64

	TaintedLocals map[string]TaintLabel

	ReturnTainted bool
	ReturnLabel   TaintLabel
}

func NewInterproceduralEngine(
	cg *callgraph.CallGraph,
	table *symboltable.SymbolTable,
	unit *parser.SourceUnit,
) *InterproceduralEngine {
	return &InterproceduralEngine{
		cg:         cg,
		table:      table,
		unit:       unit,
		taintState: make(map[callgraph.FunctionID]*functionTaintState),
	}
}

func (e *InterproceduralEngine) Analyze() []TaintFlow {
	builder := NewSummaryBuilder(e.cg, e.table)
	e.summaries = builder.BuildAll()

	for _, entry := range e.cg.EntryPoints {
		e.analyzeFunction(entry, &functionTaintState{
			TaintedLocals: make(map[string]TaintLabel),
		})
	}

	return e.flows
}

func (e *InterproceduralEngine) analyzeFunction(
	node *callgraph.FunctionNode,
	state *functionTaintState,
) {
	if node.ASTNode == nil || node.ASTNode.FunctionDef == nil {
		return
	}

	fd := node.ASTNode.FunctionDef
	params := extractParams(fd)

	if node.Visibility == "external" || node.Visibility == "public" {
		for i := range params {
			if i < 64 {
				state.TaintedParams |= 1 << uint(i)
			}
			state.TaintedLocals[params[i].name] = TaintCalldata
		}
	}

	// msg.sender, msg.value otomatik tainted
	state.TaintedLocals["msg.sender"] = TaintMsgSender
	state.TaintedLocals["msg.value"] = TaintMsgValue
	state.TaintedLocals["tx.origin"] = TaintTxOrigin

	if fd.Body != nil && fd.Body.Block != nil {
		e.analyzeBlock(fd.Body.Block, node, state)
	}
}

func (e *InterproceduralEngine) analyzeBlock(
	block *parser.Block,
	fnNode *callgraph.FunctionNode,
	state *functionTaintState,
) {
	for _, stmt := range block.Statements {
		e.analyzeStatement(stmt, fnNode, state)
	}
}

func (e *InterproceduralEngine) analyzeStatement(
	stmt *parser.ASTNode,
	fnNode *callgraph.FunctionNode,
	state *functionTaintState,
) {
	if stmt == nil {
		return
	}

	switch stmt.NodeType {

	case "VariableDeclarationStatement":
		if stmt.VarDeclStmt == nil {
			return
		}
		// RHS tainted mi?
		rhsLabel, rhsTainted := e.exprTaintLabel(
			stmt.VarDeclStmt.InitialValue, state,
		)

		if rhsTainted {
			for _, decl := range stmt.VarDeclStmt.Declarations {
				if decl != nil {
					name := extractVarNameFromNode(decl)
					if name != "" {
						state.TaintedLocals[name] = rhsLabel
					}
				}
			}
		}

		if stmt.VarDeclStmt.InitialValue != nil &&
			stmt.VarDeclStmt.InitialValue.NodeType == "FunctionCall" {
			e.handleCalleeResult(
				stmt.VarDeclStmt.Declarations,
				state,
			)
		}

	case "ExpressionStatement":
		if stmt.ExpressionStmt != nil {
			e.analyzeExpression(stmt.ExpressionStmt.Expression, fnNode, state)
		}

	case "Return":
		if stmt.ReturnStmt != nil && stmt.ReturnStmt.Expression != nil {
			label, tainted := e.exprTaintLabel(stmt.ReturnStmt.Expression, state)
			if tainted {
				state.ReturnTainted = true
				state.ReturnLabel = label
			}
		}

	case "IfStatement":
		if stmt.IfStmt != nil {
			// Her iki branch'i de analiz et
			trueState := copyState(state)
			falseState := copyState(state)

			if stmt.IfStmt.TrueBody != nil {
				e.analyzeStatement(stmt.IfStmt.TrueBody, fnNode, trueState)
			}
			if stmt.IfStmt.FalseBody != nil {
				e.analyzeStatement(stmt.IfStmt.FalseBody, fnNode, falseState)
			}

			mergeStates(state, trueState, falseState)
		}

	case "Block":
		if stmt.Block != nil {
			e.analyzeBlock(stmt.Block, fnNode, state)
		}

	case "ForStatement":
		if stmt.ForStmt != nil {
			// Analyze the loop body at least once.
			loopState := copyState(state)
			e.analyzeStatement(stmt.ForStmt.Body, fnNode, loopState)
			e.analyzeStatement(stmt.ForStmt.Body, fnNode, loopState)
			mergeStates(state, state, loopState)
		}
	}
}

func (e *InterproceduralEngine) analyzeExpression(
	expr *parser.ASTNode,
	fnNode *callgraph.FunctionNode,
	state *functionTaintState,
) {
	if expr == nil {
		return
	}

	switch expr.NodeType {
	case "Assignment":
		if expr.Assignment == nil {
			return
		}
		rhsLabel, rhsTainted := e.exprTaintLabel(expr.Assignment.RightHandSide, state)

		if rhsTainted {
			// LHS'i taint'le
			lhsName := extractBaseNameFromNode(expr.Assignment.LeftHandSide)
			if lhsName != "" {
				state.TaintedLocals[lhsName] = rhsLabel
			}
		}

		if rhsTainted {
			e.checkAssignmentSink(expr.Assignment, fnNode, rhsLabel)
		}

	case "FunctionCall":
		e.handleFunctionCall(expr, fnNode, state)
	}
}

func (e *InterproceduralEngine) handleFunctionCall(
	callNode *parser.ASTNode,
	callerNode *callgraph.FunctionNode,
	state *functionTaintState,
) {
	if callNode.FunctionCall == nil {
		return
	}

	call := callNode.FunctionCall

	cs := e.findCallSite(callerNode, callNode)
	if cs == nil {
		e.checkDirectSink(callNode, callerNode, state)
		return
	}

	taintedArgs := make([]TaintLabel, len(call.Arguments))
	anyTainted := false
	for i, arg := range call.Arguments {
		label, tainted := e.exprTaintLabel(arg, state)
		if tainted {
			taintedArgs[i] = label
			anyTainted = true
		}
	}

	switch cs.Kind {
	case callgraph.CallExternal:
		if anyTainted {
			e.recordInterproceduralFlow(
				taintedArgs, callerNode, SinkExternalCall,
			)
		}
		return
	case callgraph.CallDelegatecall:
		if anyTainted {
			e.recordInterproceduralFlow(
				taintedArgs, callerNode, SinkDelegatecall,
			)
		}
		return
	}

	if !cs.IsResolved {
		return
	}

	calleeSummary, ok := e.summaries[cs.Callee]
	if !ok {
		return
	}

	for i, label := range taintedArgs {
		if label == TaintNone {
			continue
		}
		if i >= len(calleeSummary.ParameterFlows) {
			continue
		}
		flow := calleeSummary.ParameterFlows[i]

		for _, sinkKind := range flow.ReachesSinks {
			e.flows = append(e.flows, TaintFlow{
				SourceLabel:  label,
				SinkKind:     sinkKind,
				FunctionName: callerNode.Name,
				ContractName: callerNode.Contract,
			})
		}
	}

	if anyTainted {
		calleeState := &functionTaintState{
			TaintedLocals: make(map[string]TaintLabel),
		}
		callerNode2, ok2 := e.cg.Nodes[cs.Callee]
		if ok2 {
			for i, label := range taintedArgs {
				if label != TaintNone {
					calleeState.TaintedParams |= 1 << uint(i)
					calleeParams := extractParams(callerNode2.ASTNode.FunctionDef)
					if i < len(calleeParams) {
						calleeState.TaintedLocals[calleeParams[i].name] = label
					}
				}
			}
			e.analyzeFunction(callerNode2, calleeState)

			if calleeState.ReturnTainted {
				state.TaintedLocals["__return__"] = calleeState.ReturnLabel
			}
		}
	}
}

// (bool success, bytes memory data) = addr.call{value: x}("")
func (e *InterproceduralEngine) handleCalleeResult(
	declarations []*parser.ASTNode,
	state *functionTaintState,
) {
	if len(declarations) == 0 {
		return
	}

	// Inspect the taint state for this call.
	returnLabel := state.TaintedLocals["__return__"]
	if returnLabel == TaintNone {
		return
	}

	for i, decl := range declarations {
		if i == 0 {
			continue
		}
		if decl != nil {
			name := extractVarNameFromNode(decl)
			if name != "" {
				state.TaintedLocals[name] = returnLabel
			}
		}
	}
}

func (e *InterproceduralEngine) exprTaintLabel(
	expr *parser.ASTNode,
	state *functionTaintState,
) (TaintLabel, bool) {
	if expr == nil {
		return TaintNone, false
	}

	switch expr.NodeType {
	case "Identifier":
		if expr.Identifier == nil {
			return TaintNone, false
		}
		name := expr.Identifier.Name
		if label, ok := state.TaintedLocals[name]; ok && label != TaintNone {
			return label, true
		}
		return TaintNone, false

	case "MemberAccess":
		if expr.MemberAccess == nil {
			return TaintNone, false
		}
		label, _ := detectSourceExpression(expr)
		if label != TaintNone {
			return label, true
		}
		return e.exprTaintLabel(expr.MemberAccess.Expression, state)

	case "BinaryOperation":
		if expr.BinaryOp == nil {
			return TaintNone, false
		}
		lLabel, lTainted := e.exprTaintLabel(expr.BinaryOp.LeftExpression, state)
		if lTainted {
			return lLabel, true
		}
		return e.exprTaintLabel(expr.BinaryOp.RightExpression, state)

	case "FunctionCall":
		if returnLabel, ok := state.TaintedLocals["__return__"]; ok {
			return returnLabel, true
		}
		return TaintNone, false

	case "IndexAccess":
		if expr.IndexAccess == nil {
			return TaintNone, false
		}
		return e.exprTaintLabel(expr.IndexAccess.BaseExpression, state)
	}

	return TaintNone, false
}

func (e *InterproceduralEngine) checkAssignmentSink(
	assign *parser.Assignment,
	fnNode *callgraph.FunctionNode,
	label TaintLabel,
) {
	lhsName := extractBaseNameFromNode(assign.LeftHandSide)
	for _, sym := range e.table.AllSymbols {
		if sym.IsStateVariable() && sym.Name == lhsName {
			e.flows = append(e.flows, TaintFlow{
				SourceLabel:  label,
				SinkKind:     SinkStorageWrite,
				FunctionName: fnNode.Name,
				ContractName: fnNode.Contract,
			})
			break
		}
	}
}

func (e *InterproceduralEngine) checkDirectSink(
	callNode *parser.ASTNode,
	fnNode *callgraph.FunctionNode,
	state *functionTaintState,
) {
	if callNode.FunctionCall == nil {
		return
	}
	expr := callNode.FunctionCall.Expression
	if expr == nil || expr.NodeType != "MemberAccess" || expr.MemberAccess == nil {
		return
	}

	var sinkKind SinkKind
	switch expr.MemberAccess.MemberName {
	case "call":
		sinkKind = SinkExternalCall
	case "transfer", "send":
		sinkKind = SinkETHTransfer
	case "delegatecall":
		sinkKind = SinkDelegatecall
	default:
		return
	}

	for _, arg := range callNode.FunctionCall.Arguments {
		label, tainted := e.exprTaintLabel(arg, state)
		if tainted {
			e.flows = append(e.flows, TaintFlow{
				SourceLabel:  label,
				SinkKind:     sinkKind,
				FunctionName: fnNode.Name,
				ContractName: fnNode.Contract,
			})
		}
	}
}

func (e *InterproceduralEngine) recordInterproceduralFlow(
	argLabels []TaintLabel,
	caller *callgraph.FunctionNode,
	sinkKind SinkKind,
) {
	for _, label := range argLabels {
		if label == TaintNone {
			continue
		}
		e.flows = append(e.flows, TaintFlow{
			SourceLabel:  label,
			SinkKind:     sinkKind,
			FunctionName: caller.Name,
			ContractName: caller.Contract,
		})
	}
}

func (e *InterproceduralEngine) findCallSite(
	caller *callgraph.FunctionNode,
	callNode *parser.ASTNode,
) *callgraph.CallSite {
	for _, cs := range caller.Callees {
		if cs.CallNode == callNode {
			return cs
		}
	}
	return nil
}

func copyState(s *functionTaintState) *functionTaintState {
	locals := make(map[string]TaintLabel, len(s.TaintedLocals))
	for k, v := range s.TaintedLocals {
		locals[k] = v
	}
	return &functionTaintState{
		TaintedParams: s.TaintedParams,
		TaintedLocals: locals,
		ReturnTainted: s.ReturnTainted,
		ReturnLabel:   s.ReturnLabel,
	}
}

// Conservative join: her iki branch'ten gelen taint'leri topla.
func mergeStates(dst, a, b *functionTaintState) {
	dst.TaintedParams = a.TaintedParams | b.TaintedParams
	if b.ReturnTainted {
		dst.ReturnTainted = true
		dst.ReturnLabel = b.ReturnLabel
	}
	for k, v := range b.TaintedLocals {
		dst.TaintedLocals[k] = v
	}
}

func extractVarNameFromNode(node *parser.ASTNode) string {
	return parser.VariableName(node)
}

func extractBaseNameFromNode(node *parser.ASTNode) string {
	return parser.BaseIdentifierName(node)
}
