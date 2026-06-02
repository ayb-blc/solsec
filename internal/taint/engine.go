package taint

import (
	"fmt"

	"github.com/ayb-blc/solsec/internal/parser"
	"github.com/ayb-blc/solsec/internal/symboltable"
)

type Engine struct {
	table *symboltable.SymbolTable
	unit  *parser.SourceUnit

	taintMap map[int]*TaintedValue

	flows []TaintFlow

	worklist []*symboltable.Symbol

	orderDB *symboltable.StatementOrderDB
	indexDB *symboltable.IndexDB

	propagator *OrderedPropagator
}

func NewEngine(table *symboltable.SymbolTable, unit *parser.SourceUnit) *Engine {
	return &Engine{
		table:    table,
		unit:     unit,
		taintMap: make(map[int]*TaintedValue),
	}
}

func (e *Engine) Analyze() []TaintFlow {
	e.seedSources()

	e.propagate()

	e.checkSinks()

	return e.flows
}

// =========================================================
// =========================================================

func (e *Engine) seedSources() {
	seeder := &sourceSeeder{engine: e}
	for _, node := range e.unit.Nodes {
		parser.WalkWithContext(node, parser.NewContextualVisitor(seeder))
	}
}

type sourceSeeder struct {
	engine          *Engine
	currentFn       string
	currentContract string
}

func (ss *sourceSeeder) HandleNode(ctx *parser.AnalysisContext, node *parser.ASTNode) bool {
	if node == nil {
		return false
	}

	if ctx.CurrentContract() != nil {
		ss.currentContract = ctx.CurrentContract().Name
	}
	if ctx.CurrentFunction() != nil {
		ss.currentFn = ctx.CurrentFunction().Name
	}

	switch node.NodeType {

	case "FunctionDefinition":
		if node.FunctionDef == nil {
			return true
		}
		fd := node.FunctionDef
		visibility := fd.Visibility
		if visibility == "external" || visibility == "public" {
			ss.seedParameters(fd)
		}
		return true

	case "Assignment":
		if node.Assignment != nil {
			ss.checkAssignmentForSource(node.Assignment)
		}
		return true

	case "VariableDeclarationStatement":
		// uint256 amount = msg.value pattern'i
		if node.VarDeclStmt != nil {
			ss.checkVarDeclForSource(node.VarDeclStmt)
		}
		return true
	}

	return true
}

func (ss *sourceSeeder) seedParameters(fd *parser.FunctionDefinition) {
	if fd.Parameters == nil {
		return
	}

	for _, param := range fd.Parameters.Parameters {
		// Symbol table'dan bu parametreyi bul
		sym := ss.engine.findSymbolByID(param.ID)
		if sym == nil {
			// ID ile bulamazsan isim ile dene
			sym = ss.engine.findSymbolByName(param.Name, fd.Name)
		}
		if sym == nil {
			continue
		}

		source := TaintSource{
			Label: TaintCalldata,
			Description: fmt.Sprintf(
				"Function parameter '%s' of external function '%s' — "+
					"directly controlled by the caller",
				param.Name, fd.Name,
			),
		}

		ss.engine.taintSymbol(sym, source, nil)
	}
}

func (ss *sourceSeeder) checkAssignmentForSource(assign *parser.Assignment) {
	label, sourceNode := detectSourceExpression(assign.RightHandSide)
	if label == TaintNone {
		return
	}

	baseName := parser.BaseIdentifierName(assign.LeftHandSide)
	if baseName == "" {
		return
	}

	sym := ss.engine.findSymbolByName(baseName, ss.currentFn)
	if sym == nil {
		return
	}

	source := TaintSource{
		Label:      label,
		OriginNode: sourceNode,
		Description: fmt.Sprintf(
			"'%s' assigned from taint source '%s' in function '%s'",
			baseName, label, ss.currentFn,
		),
	}
	ss.engine.taintSymbol(sym, source, nil)
}

func (ss *sourceSeeder) checkVarDeclForSource(stmt *parser.VariableDeclarationStatement) {
	if stmt.InitialValue == nil {
		return
	}

	label, sourceNode := detectSourceExpression(stmt.InitialValue)
	if label == TaintNone {
		return
	}

	for _, declNode := range stmt.Declarations {
		if declNode == nil {
			continue
		}
		name := parser.VariableName(declNode)
		if name == "" {
			continue
		}

		sym := ss.engine.findSymbolByIDOrName(declNode.ID, name, ss.currentFn)
		if sym == nil {
			continue
		}

		source := TaintSource{
			Label:      label,
			OriginNode: sourceNode,
			Description: fmt.Sprintf(
				"Variable '%s' initialized from taint source '%s'",
				name, label,
			),
		}
		ss.engine.taintSymbol(sym, source, nil)
	}
}

func detectSourceExpression(node *parser.ASTNode) (TaintLabel, *parser.ASTNode) {
	if node == nil {
		return TaintNone, nil
	}

	if node.NodeType != "MemberAccess" || node.MemberAccess == nil {
		return TaintNone, nil
	}

	ma := node.MemberAccess
	if ma.Expression == nil ||
		ma.Expression.NodeType != "Identifier" ||
		ma.Expression.Identifier == nil {
		return TaintNone, nil
	}

	object := ma.Expression.Identifier.Name
	member := ma.MemberName

	switch object {
	case "msg":
		switch member {
		case "sender":
			return TaintMsgSender, node
		case "value":
			return TaintMsgValue, node
		case "data":
			return TaintMsgData, node
		}
	case "tx":
		if member == "origin" {
			return TaintTxOrigin, node
		}
	case "block":
		switch member {
		case "timestamp":
			return TaintBlockTimestamp, node
		case "number":
			return TaintBlockNumber, node
		}
	}

	return TaintNone, nil
}

// =========================================================
// =========================================================

func (e *Engine) propagate() {
	for len(e.worklist) > 0 {
		sym := e.worklist[0]
		e.worklist = e.worklist[1:]

		for _, usage := range sym.Reads {
			e.propagateFromUsage(sym, usage)
		}
	}
}

func (e *Engine) propagateFromUsage(src *symboltable.Symbol, usage symboltable.Usage) {
	if usage.Node == nil {
		return
	}

	// Usage node'unun context'ini bul
	//
	//

	for _, candidate := range e.table.AllSymbols {
		if e.isTaintedByFull(candidate, src) {
			if !e.isTainted(candidate) {
				srcTaint := e.taintMap[src.SolcID]
				var chain []*symboltable.Symbol
				if srcTaint != nil {
					chain = append(srcTaint.PropagationChain, src)
				}

				source := TaintSource{
					Label: TaintDerived,
					Description: fmt.Sprintf(
						"Derived from '%s' which is tainted by %s",
						src.Name,
						e.taintMap[src.SolcID].HighestRiskSource().Label,
					),
				}
				e.taintSymbolWithChain(candidate, source, chain)
			}
		}
	}
}

// =========================================================
// =========================================================

// Sink pattern'leri:
func (e *Engine) checkSinks() {
	checker := &sinkChecker{engine: e}
	for _, node := range e.unit.Nodes {
		parser.WalkWithContext(node, parser.NewContextualVisitor(checker))
	}
}

// sinkChecker AST'yi gezerek sink pattern'lerini arayan visitor
type sinkChecker struct {
	engine          *Engine
	currentFn       string
	currentContract string
}

func (sc *sinkChecker) HandleNode(ctx *parser.AnalysisContext, node *parser.ASTNode) bool {
	if node == nil {
		return false
	}

	if ctx.CurrentContract() != nil {
		sc.currentContract = ctx.CurrentContract().Name
	}
	if ctx.CurrentFunction() != nil {
		sc.currentFn = ctx.CurrentFunction().Name
	}

	if node.NodeType == "FunctionCall" && node.FunctionCall != nil {
		sc.checkFunctionCallSink(node)
	}

	return true
}

func (sc *sinkChecker) checkFunctionCallSink(node *parser.ASTNode) {
	call := node.FunctionCall
	if call == nil || call.Expression == nil {
		return
	}

	expr := call.Expression

	if expr.NodeType == "MemberAccess" && expr.MemberAccess != nil {
		member := expr.MemberAccess.MemberName

		switch member {
		case "call", "staticcall":
			sc.checkCallArguments(node, call, SinkExternalCall)

			sc.checkCallValueOption(node, expr, SinkETHTransfer)

		case "transfer", "send":
			// addr.transfer(tainted_amount)
			if len(call.Arguments) > 0 {
				sc.checkArgumentTaint(node, call.Arguments[0], SinkETHTransfer)
			}

		case "delegatecall":
			sc.checkCallArguments(node, call, SinkDelegatecall)

			sc.checkReceiverTaint(node, expr.MemberAccess.Expression, SinkDelegatecall)
		}
	}

	// Pattern 2: selfdestruct(tainted_addr)
	if expr.NodeType == "Identifier" && expr.Identifier != nil {
		switch expr.Identifier.Name {
		case "selfdestruct", "suicide":
			if len(call.Arguments) > 0 {
				sc.checkArgumentTaint(node, call.Arguments[0], SinkSelfdestruct)
			}

		case "require", "assert":
			if len(call.Arguments) > 0 {
				sc.checkAccessControlTaint(node, call.Arguments[0])
			}
		}
	}
}

func (sc *sinkChecker) checkCallArguments(
	callNode *parser.ASTNode,
	call *parser.FunctionCall,
	sinkKind SinkKind,
) {
	for _, arg := range call.Arguments {
		sc.checkArgumentTaint(callNode, arg, sinkKind)
	}
}

// checkCallValueOption handles value/options encoded as FunctionCallOptions in the solc AST.
func (sc *sinkChecker) checkCallValueOption(
	callNode *parser.ASTNode,
	memberAccess *parser.ASTNode,
	sinkKind SinkKind,
) {
	// FunctionCall {
	//   expression: FunctionCallOptions {
	//     expression: MemberAccess{..., "call"},
	//     options: {"value": <expression>}
	//   }
	// }
	if memberAccess.MemberAccess != nil {
		sc.checkArgumentTaint(callNode, memberAccess.MemberAccess.Expression, sinkKind)
	}
}

func (sc *sinkChecker) checkArgumentTaint(
	sinkNode *parser.ASTNode,
	argNode *parser.ASTNode,
	sinkKind SinkKind,
) {
	if argNode == nil {
		return
	}

	if argNode.NodeType == "Identifier" && argNode.Identifier != nil {
		sym := sc.engine.findSymbolByIDOrName(
			argNode.Identifier.ReferencedDeclaration,
			argNode.Identifier.Name,
			sc.currentFn,
		)
		if sym != nil && sc.engine.isTainted(sym) {
			sc.recordFlow(sym, sinkNode, sinkKind)
		}
		return
	}

	if argNode.NodeType == "BinaryOperation" && argNode.BinaryOp != nil {
		sc.checkArgumentTaint(sinkNode, argNode.BinaryOp.LeftExpression, sinkKind)
		sc.checkArgumentTaint(sinkNode, argNode.BinaryOp.RightExpression, sinkKind)
		return
	}

	label, _ := detectSourceExpression(argNode)
	if label != TaintNone {
		sc.recordDirectSourceFlow(label, argNode, sinkNode, sinkKind)
	}
}

func (sc *sinkChecker) checkReceiverTaint(
	sinkNode *parser.ASTNode,
	receiverNode *parser.ASTNode,
	sinkKind SinkKind,
) {
	if receiverNode == nil {
		return
	}
	sc.checkArgumentTaint(sinkNode, receiverNode, sinkKind)
}

func (sc *sinkChecker) checkAccessControlTaint(sinkNode, conditionNode *parser.ASTNode) {
	if conditionNode == nil {
		return
	}

	// Binary operation: tainted == x or x == tainted.
	if conditionNode.NodeType == "BinaryOperation" && conditionNode.BinaryOp != nil {
		bo := conditionNode.BinaryOp
		if bo.Operator != "==" && bo.Operator != "!=" {
			return
		}

		leftLabel, _ := detectSourceExpression(bo.LeftExpression)
		rightLabel, _ := detectSourceExpression(bo.RightExpression)

		// Bunu raporlama
		if leftLabel == TaintMsgSender || rightLabel == TaintMsgSender {
			return
		}

		sc.checkArgumentTaint(sinkNode, bo.LeftExpression, SinkAccessControl)
		sc.checkArgumentTaint(sinkNode, bo.RightExpression, SinkAccessControl)
	}
}

// recordFlow records one taint flow.
func (sc *sinkChecker) recordFlow(
	sym *symboltable.Symbol,
	sinkNode *parser.ASTNode,
	sinkKind SinkKind,
) {
	taintedVal, ok := sc.engine.taintMap[sym.SolcID]
	if !ok {
		return
	}

	flow := TaintFlow{
		SourceLabel:  taintedVal.HighestRiskSource().Label,
		SourceNode:   taintedVal.HighestRiskSource().OriginNode,
		Chain:        append(taintedVal.PropagationChain, sym),
		SinkNode:     sinkNode,
		SinkKind:     sinkKind,
		FunctionName: sc.currentFn,
		ContractName: sc.currentContract,
	}
	sc.engine.flows = append(sc.engine.flows, flow)

	taintedVal.ReachesSink = true
	taintedVal.SinkNode = sinkNode
	taintedVal.SinkKind = sinkKind
}

func (sc *sinkChecker) recordDirectSourceFlow(
	label TaintLabel,
	sourceNode, sinkNode *parser.ASTNode,
	sinkKind SinkKind,
) {
	flow := TaintFlow{
		SourceLabel:  label,
		SourceNode:   sourceNode,
		SinkNode:     sinkNode,
		SinkKind:     sinkKind,
		FunctionName: sc.currentFn,
		ContractName: sc.currentContract,
	}
	sc.engine.flows = append(sc.engine.flows, flow)
}

// =========================================================
// =========================================================

func (e *Engine) taintSymbol(sym *symboltable.Symbol, source TaintSource, chain []*symboltable.Symbol) {
	e.taintSymbolWithChain(sym, source, chain)
}

func (e *Engine) taintSymbolWithChain(
	sym *symboltable.Symbol,
	source TaintSource,
	chain []*symboltable.Symbol,
) {
	tv, exists := e.taintMap[sym.SolcID]
	if !exists {
		tv = &TaintedValue{
			Symbol:           sym,
			PropagationChain: chain,
		}
		e.taintMap[sym.SolcID] = tv
		e.worklist = append(e.worklist, sym)
	}
	tv.AddSource(source)
	sym.IsUserControlled = true
}

func (e *Engine) isTainted(sym *symboltable.Symbol) bool {
	_, ok := e.taintMap[sym.SolcID]
	return ok
}

func (e *Engine) findSymbolByID(id int) *symboltable.Symbol {
	for _, sym := range e.table.AllSymbols {
		if sym.SolcID == id {
			return sym
		}
	}
	return nil
}

func (e *Engine) findSymbolByName(name, fnName string) *symboltable.Symbol {
	for _, sym := range e.table.AllSymbols {
		if sym.Name == name {
			if fnName == "" {
				return sym
			}
			if sym.DeclaredInScope != nil {
				if fnScope := sym.DeclaredInScope.FunctionScope(); fnScope != nil {
					if fnScope.Name == fnName {
						return sym
					}
				}
			}
		}
	}
	return nil
}

func (e *Engine) findSymbolByIDOrName(id int, name, fnName string) *symboltable.Symbol {
	if id != 0 {
		if sym := e.findSymbolByID(id); sym != nil {
			return sym
		}
	}
	return e.findSymbolByName(name, fnName)
}
