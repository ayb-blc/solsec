package callgraph

import (
	"github.com/ayb-blc/solsec/internal/parser"
	"github.com/ayb-blc/solsec/internal/symboltable"
)

type Builder struct {
	graph *CallGraph
	table *symboltable.SymbolTable
	unit  *parser.SourceUnit

	currentContract string

	currentFunction FunctionID
}

func Build(unit *parser.SourceUnit, table *symboltable.SymbolTable) (*CallGraph, error) {
	b := &Builder{
		graph: NewCallGraph(),
		table: table,
		unit:  unit,
	}

	b.collectFunctionNodes()

	b.collectCallEdges()

	b.computeTransitiveProperties()

	// Pass 4: Cycle detection
	b.detectCycles()

	return b.graph, nil
}

// =========================================================
// =========================================================

func (b *Builder) collectFunctionNodes() {
	for _, node := range b.unit.Nodes {
		if node.NodeType == "ContractDefinition" && node.ContractDef != nil {
			b.collectContractFunctions(node.ContractDef)
		}
	}
}

func (b *Builder) collectContractFunctions(contract *parser.ContractDefinition) {
	for _, node := range contract.Nodes {
		switch node.NodeType {

		case "FunctionDefinition":
			if node.FunctionDef == nil {
				continue
			}
			fd := node.FunctionDef
			fnName := fd.Name

			if fd.Kind == "constructor" {
				fnName = "constructor"
			} else if fd.Kind == "fallback" {
				fnName = "fallback"
			} else if fd.Kind == "receive" {
				fnName = "receive"
			}

			id := NewFunctionID(contract.Name, fnName)
			fnNode := &FunctionNode{
				ID:         id,
				Name:       fnName,
				Contract:   contract.Name,
				Visibility: fd.Visibility,
				Mutability: fd.StateMutability,
				IsModifier: false,
				ASTNode:    node,
			}
			b.graph.AddNode(fnNode)

		case "ModifierDefinition":
			if node.ModifierDef == nil {
				continue
			}
			md := node.ModifierDef
			id := NewFunctionID(contract.Name, "modifier:"+md.Name)
			modNode := &FunctionNode{
				ID:         id,
				Name:       md.Name,
				Contract:   contract.Name,
				Visibility: "internal",
				IsModifier: true,
				ASTNode:    node,
			}
			b.graph.AddNode(modNode)
		}
	}
}

// =========================================================
// PASS 2: Call Edge Toplama
// =========================================================

func (b *Builder) collectCallEdges() {
	for _, node := range b.unit.Nodes {
		if node.NodeType == "ContractDefinition" && node.ContractDef != nil {
			b.currentContract = node.ContractDef.Name
			b.collectContractCallEdges(node.ContractDef)
		}
	}
}

func (b *Builder) collectContractCallEdges(contract *parser.ContractDefinition) {
	for _, node := range contract.Nodes {
		switch node.NodeType {
		case "FunctionDefinition":
			if node.FunctionDef != nil {
				fnName := node.FunctionDef.Name
				if node.FunctionDef.Kind == "constructor" {
					fnName = "constructor"
				}
				b.currentFunction = NewFunctionID(contract.Name, fnName)
				b.walkForCalls(node.FunctionDef.Body)
			}
		case "ModifierDefinition":
			if node.ModifierDef != nil {
				b.currentFunction = NewFunctionID(
					contract.Name,
					"modifier:"+node.ModifierDef.Name,
				)
				b.walkForCalls(node.ModifierDef.Body)
			}
		}
	}
}

// walkForCalls recursively visits an AST node and records resolvable call edges.
func (b *Builder) walkForCalls(node *parser.ASTNode) {
	if node == nil {
		return
	}

	switch node.NodeType {

	case "FunctionCall":
		if node.FunctionCall != nil {
			b.processFunctionCall(node)
		}
		if node.FunctionCall != nil {
			for _, arg := range node.FunctionCall.Arguments {
				b.walkForCalls(arg)
			}
		}

	case "Block":
		if node.Block != nil {
			for _, stmt := range node.Block.Statements {
				b.walkForCalls(stmt)
			}
		}

	case "ExpressionStatement":
		if node.ExpressionStmt != nil {
			b.walkForCalls(node.ExpressionStmt.Expression)
		}

	case "VariableDeclarationStatement":
		if node.VarDeclStmt != nil {
			b.walkForCalls(node.VarDeclStmt.InitialValue)
		}

	case "Return":
		if node.ReturnStmt != nil {
			b.walkForCalls(node.ReturnStmt.Expression)
		}

	case "IfStatement":
		if node.IfStmt != nil {
			b.walkForCalls(node.IfStmt.Condition)
			b.walkForCalls(node.IfStmt.TrueBody)
			b.walkForCalls(node.IfStmt.FalseBody)
		}

	case "ForStatement":
		if node.ForStmt != nil {
			b.walkForCalls(node.ForStmt.InitializationExpression)
			b.walkForCalls(node.ForStmt.Condition)
			b.walkForCalls(node.ForStmt.Body)
			b.walkForCalls(node.ForStmt.LoopExpression)
		}

	case "Assignment":
		if node.Assignment != nil {
			b.walkForCalls(node.Assignment.RightHandSide)
		}

	case "BinaryOperation":
		if node.BinaryOp != nil {
			b.walkForCalls(node.BinaryOp.LeftExpression)
			b.walkForCalls(node.BinaryOp.RightExpression)
		}

	case "TupleExpression":
		if node.TupleExpression != nil {
			for _, comp := range node.TupleExpression.Components {
				b.walkForCalls(comp)
			}
		}

	case "MemberAccess":
		if node.MemberAccess != nil {
			b.walkForCalls(node.MemberAccess.Expression)
		}
	}
}

// 1. Internal call:
//
// 4. Library call:
//
// 5. Built-in:
func (b *Builder) processFunctionCall(node *parser.ASTNode) {
	call := node.FunctionCall
	if call == nil || call.Expression == nil {
		return
	}

	expr := call.Expression

	switch expr.NodeType {

	case "Identifier":
		b.processIdentifierCall(node, call, expr)

	case "MemberAccess":
		b.processMemberAccessCall(node, call, expr)
	}
}

func (b *Builder) processIdentifierCall(
	callNode *parser.ASTNode,
	call *parser.FunctionCall,
	identNode *parser.ASTNode,
) {
	if identNode.Identifier == nil {
		return
	}

	name := identNode.Identifier.Name

	if isBuiltin(name) {
		return
	}

	calleeID := NewFunctionID(b.currentContract, name)
	_, resolved := b.graph.Nodes[calleeID]

	if !resolved {
		calleeID, resolved = b.resolveInheritedFunction(name)
	}

	cs := &CallSite{
		Caller:        b.currentFunction,
		Callee:        calleeID,
		Kind:          CallInternal,
		CallNode:      callNode,
		ArgumentNodes: call.Arguments,
		IsResolved:    resolved,
	}
	b.graph.AddCallSite(cs)

}

func (b *Builder) processMemberAccessCall(
	callNode *parser.ASTNode,
	call *parser.FunctionCall,
	memberNode *parser.ASTNode,
) {
	if memberNode.MemberAccess == nil {
		return
	}

	ma := memberNode.MemberAccess
	memberName := ma.MemberName

	// Low-level external call'lar: .call, .delegatecall, .staticcall, .transfer, .send
	switch memberName {
	case "call", "transfer", "send":
		b.recordLowLevelExternalCall(callNode, call, memberName, CallExternal)
		return
	case "delegatecall":
		b.recordLowLevelExternalCall(callNode, call, memberName, CallDelegatecall)
		return
	case "staticcall":
		b.recordLowLevelExternalCall(callNode, call, memberName, CallStaticall)
		return
	}

	if ma.Expression != nil &&
		ma.Expression.NodeType == "Identifier" &&
		ma.Expression.Identifier != nil {

		objName := ma.Expression.Identifier.Name
		if isBuiltinObject(objName) {
			return
		}

		libCalleeID := NewFunctionID(objName, memberName)
		if _, isLib := b.graph.Nodes[libCalleeID]; isLib {
			cs := &CallSite{
				Caller:        b.currentFunction,
				Callee:        libCalleeID,
				Kind:          CallLibrary,
				CallNode:      callNode,
				ArgumentNodes: call.Arguments,
				IsResolved:    true,
			}
			b.graph.AddCallSite(cs)
			return
		}

		cs := &CallSite{
			Caller:        b.currentFunction,
			Kind:          CallVirtual,
			CallNode:      callNode,
			ArgumentNodes: call.Arguments,
			IsResolved:    false,
		}
		b.graph.AddCallSite(cs)

		if callerNode, ok := b.graph.Nodes[b.currentFunction]; ok {
			callerNode.HasExternalCall = true
		}
	}
}

func (b *Builder) recordLowLevelExternalCall(
	callNode *parser.ASTNode,
	call *parser.FunctionCall,
	memberName string,
	kind CallKind,
) {
	cs := &CallSite{
		Caller:        b.currentFunction,
		Kind:          kind,
		CallNode:      callNode,
		ArgumentNodes: call.Arguments,
		IsResolved:    false,
	}
	b.graph.AddCallSite(cs)

	if callerNode, ok := b.graph.Nodes[b.currentFunction]; ok {
		callerNode.HasExternalCall = true
	}
}

func (b *Builder) resolveInheritedFunction(name string) (FunctionID, bool) {
	for id, node := range b.graph.Nodes {
		if node.Name == name && !node.IsModifier {
			return id, true
		}
	}
	return FunctionID(""), false
}

// =========================================================
// PASS 3: Transitive Property Hesaplama
// =========================================================

func (b *Builder) computeTransitiveProperties() {
	visited := make(map[FunctionID]bool)
	inStack := make(map[FunctionID]bool)

	for id := range b.graph.Nodes {
		b.computeNodeProperties(id, visited, inStack)
	}

	reachable := make(map[FunctionID]bool)
	for _, entry := range b.graph.EntryPoints {
		b.markReachable(entry.ID, reachable)
	}
	for id, node := range b.graph.Nodes {
		node.IsReachableFromExternal = reachable[id]
	}
}

func (b *Builder) computeNodeProperties(
	id FunctionID,
	visited map[FunctionID]bool,
	inStack map[FunctionID]bool,
) {
	if visited[id] {
		return
	}
	if inStack[id] {
		return
	}

	inStack[id] = true
	defer func() { inStack[id] = false }()

	node, ok := b.graph.Nodes[id]
	if !ok {
		return
	}

	for _, cs := range node.Callees {
		if cs.IsResolved {
			b.computeNodeProperties(cs.Callee, visited, inStack)
		}
	}

	hasExtCall := node.HasExternalCall
	hasStateWr := node.HasStateWrite

	for _, cs := range node.Callees {
		if !cs.IsResolved {
			hasExtCall = true
			continue
		}
		if calleeNode, exists := b.graph.Nodes[cs.Callee]; exists {
			if calleeNode.TransitiveExternalCall {
				hasExtCall = true
			}
			if calleeNode.TransitiveStateWrite {
				hasStateWr = true
			}
		}
	}

	node.TransitiveExternalCall = hasExtCall
	node.TransitiveStateWrite = hasStateWr
	visited[id] = true
}

func (b *Builder) markReachable(id FunctionID, reachable map[FunctionID]bool) {
	if reachable[id] {
		return
	}
	reachable[id] = true

	node, ok := b.graph.Nodes[id]
	if !ok {
		return
	}
	for _, cs := range node.Callees {
		if cs.IsResolved {
			b.markReachable(cs.Callee, reachable)
		}
	}
}

// =========================================================
// =========================================================

type tarjanState struct {
	index   map[FunctionID]int
	lowlink map[FunctionID]int
	onStack map[FunctionID]bool
	stack   []FunctionID
	sccs    [][]FunctionID
	counter int
}

func (b *Builder) detectCycles() {
	state := &tarjanState{
		index:   make(map[FunctionID]int),
		lowlink: make(map[FunctionID]int),
		onStack: make(map[FunctionID]bool),
	}

	for id := range b.graph.Nodes {
		if _, visited := state.index[id]; !visited {
			b.tarjanDFS(id, state)
		}
	}

	for _, scc := range state.sccs {
		if len(scc) > 1 {
			b.graph.Cycles = append(b.graph.Cycles, scc)
		}
	}
}

func (b *Builder) tarjanDFS(id FunctionID, state *tarjanState) {
	state.index[id] = state.counter
	state.lowlink[id] = state.counter
	state.counter++
	state.stack = append(state.stack, id)
	state.onStack[id] = true

	node, ok := b.graph.Nodes[id]
	if !ok {
		return
	}

	for _, cs := range node.Callees {
		if !cs.IsResolved {
			continue
		}
		w := cs.Callee

		if _, visited := state.index[w]; !visited {
			b.tarjanDFS(w, state)
			if state.lowlink[w] < state.lowlink[id] {
				state.lowlink[id] = state.lowlink[w]
			}
		} else if state.onStack[w] {
			if state.index[w] < state.lowlink[id] {
				state.lowlink[id] = state.index[w]
			}
		}
	}

	// SCC root'u bulduk
	if state.lowlink[id] == state.index[id] {
		var scc []FunctionID
		for {
			w := state.stack[len(state.stack)-1]
			state.stack = state.stack[:len(state.stack)-1]
			state.onStack[w] = false
			scc = append(scc, w)
			if w == id {
				break
			}
		}
		state.sccs = append(state.sccs, scc)
	}
}

// =========================================================
// =========================================================

func isBuiltin(name string) bool {
	builtins := map[string]bool{
		"require": true, "assert": true, "revert": true,
		"keccak256": true, "sha256": true, "ripemd160": true,
		"ecrecover": true, "addmod": true, "mulmod": true,
		"selfdestruct": true, "suicide": true,
		"blockhash": true, "gasleft": true,
		"type": true, "abi": true,
	}
	return builtins[name]
}

func isBuiltinObject(name string) bool {
	objects := map[string]bool{
		"abi": true, "block": true, "msg": true,
		"tx": true, "type": true,
	}
	return objects[name]
}
