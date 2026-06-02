package symboltable

import (
	"fmt"
	"strings"

	"github.com/ayb-blc/solsec/internal/parser"
)

type SymbolTable struct {
	GlobalScope *Scope

	AllScopes map[ScopeID]*Scope

	AllSymbols []*Symbol

	nextScopeID ScopeID

	SourceMap *parser.SourceMap

	sourceUnit *parser.SourceUnit

	ScopeExts         map[ScopeID]*ScopeWithExt
	ContractScopes    map[string]*ScopeWithExt
	FunctionScopeExts map[ScopeID]*ScopeWithExt
	StatementOrder    *StatementOrderDB
}

func NewSymbolTable(srcMap *parser.SourceMap) *SymbolTable {
	st := &SymbolTable{
		AllScopes:         make(map[ScopeID]*Scope),
		SourceMap:         srcMap,
		ScopeExts:         make(map[ScopeID]*ScopeWithExt),
		ContractScopes:    make(map[string]*ScopeWithExt),
		FunctionScopeExts: make(map[ScopeID]*ScopeWithExt),
		StatementOrder:    NewStatementOrderDB(),
	}
	st.GlobalScope = st.newScope(ScopeGlobal, "global", nil)
	return st
}

func (st *SymbolTable) newScope(kind ScopeKind, name string, parent *Scope) *Scope {
	id := st.nextScopeID
	st.nextScopeID++
	scope := NewScope(id, kind, name, parent)
	st.AllScopes[id] = scope
	ext := newScopeExtension(scope)
	st.ScopeExts[id] = ext
	st.StatementOrder.RegisterScope(scope)
	switch kind {
	case ScopeContract:
		st.ContractScopes[name] = ext
	case ScopeFunction:
		st.FunctionScopeExts[id] = ext
	}
	return scope
}

// - Local variable'lar
// - Parametreler
type Builder struct {
	table        *SymbolTable
	currentScope *Scope

	statementIndex int

	externalCallSeen bool
}

func Build(unit *parser.SourceUnit, srcMap *parser.SourceMap) (*SymbolTable, error) {
	st := NewSymbolTable(srcMap)
	st.sourceUnit = unit
	b := &Builder{
		table:        st,
		currentScope: st.GlobalScope,
	}

	if err := b.collectDeclarations(unit); err != nil {
		return nil, fmt.Errorf("pass 1 (collect declarations) failed: %w", err)
	}
	b.resolveAllAncestors(st.ContractScopes)

	if err := b.resolveReferences(unit); err != nil {
		return nil, fmt.Errorf("pass 2 (resolve references) failed: %w", err)
	}

	return st, nil
}

// =========================================================
// PASS 1: Declaration Collector
// =========================================================

func (b *Builder) collectDeclarations(unit *parser.SourceUnit) error {
	for _, node := range unit.Nodes {
		if err := b.collectNode(node); err != nil {
			return err
		}
	}
	return nil
}

func (b *Builder) collectNode(node *parser.ASTNode) error {
	if node == nil {
		return nil
	}

	switch node.NodeType {

	case "ContractDefinition":
		return b.collectContract(node)

	case "FunctionDefinition":
		return b.collectFunction(node)

	case "ModifierDefinition":
		return b.collectModifier(node)

	case "StateVariableDeclaration":
		return b.collectStateVariable(node)

	case "VariableDeclarationStatement":
		return b.collectLocalVariable(node)

	case "Block":
		return b.collectBlock(node)

	case "IfStatement":
		if node.IfStmt != nil {
			if err := b.collectNode(node.IfStmt.TrueBody); err != nil {
				return err
			}
			return b.collectNode(node.IfStmt.FalseBody)
		}

	case "ForStatement":
		if node.ForStmt != nil {
			if err := b.collectNode(node.ForStmt.InitializationExpression); err != nil {
				return err
			}
			return b.collectNode(node.ForStmt.Body)
		}
	}

	return nil
}

func (b *Builder) collectContract(node *parser.ASTNode) error {
	if node.ContractDef == nil {
		return nil
	}
	cd := node.ContractDef

	contractScope := b.table.newScope(ScopeContract, cd.Name, b.currentScope)
	if ext := b.table.ScopeExts[contractScope.ID]; ext != nil {
		b.collectContractInheritance(node, ext)
	}

	prev := b.currentScope
	b.currentScope = contractScope
	defer func() { b.currentScope = prev }()

	for _, child := range cd.Nodes {
		if err := b.collectNode(child); err != nil {
			return err
		}
	}
	return nil
}

func (b *Builder) collectFunction(node *parser.ASTNode) error {
	if node.FunctionDef == nil {
		return nil
	}
	fd := node.FunctionDef

	fnSymbol := &Symbol{
		Name:            fd.Name,
		Kind:            KindFunction,
		SolcID:          node.ID,
		Visibility:      fd.Visibility,
		DeclarationNode: node,
	}
	if err := b.currentScope.Define(fnSymbol); err != nil {
		return err
	}
	b.table.AllSymbols = append(b.table.AllSymbols, fnSymbol)

	fnScope := b.table.newScope(ScopeFunction, fd.Name, b.currentScope)
	if ext := b.table.ScopeExts[fnScope.ID]; ext != nil {
		b.collectFunctionModifiers(fd, ext)
	}
	if fd.Body != nil && fd.Body.Block != nil {
		b.table.StatementOrder.Register(fnScope.ID, buildStatementOrder(fd.Body.Block))
	}

	prev := b.currentScope
	b.currentScope = fnScope
	defer func() { b.currentScope = prev }()

	if fd.Parameters != nil {
		for _, param := range fd.Parameters.Parameters {
			paramSymbol := &Symbol{
				Name:             param.Name,
				Kind:             KindParameter,
				SolcID:           param.ID,
				TypeName:         parser.TypeNameString(param.TypeName),
				StorageLocation:  parseStorageLocation(param.StorageLocation),
				DeclarationNode:  &parser.ASTNode{},
				IsUserControlled: param.StorageLocation == "calldata",
			}
			if err := b.currentScope.Define(paramSymbol); err != nil {
				return err
			}
			b.table.AllSymbols = append(b.table.AllSymbols, paramSymbol)
		}
	}

	if fd.Body != nil {
		return b.collectNode(fd.Body)
	}
	return nil
}

func (b *Builder) collectModifier(node *parser.ASTNode) error {
	if node.ModifierDef == nil {
		return nil
	}
	md := node.ModifierDef

	modSymbol := &Symbol{
		Name:            md.Name,
		Kind:            KindModifier,
		SolcID:          node.ID,
		DeclarationNode: node,
	}
	if err := b.currentScope.Define(modSymbol); err != nil {
		return err
	}
	b.table.AllSymbols = append(b.table.AllSymbols, modSymbol)

	modScope := b.table.newScope(ScopeModifier, md.Name, b.currentScope)
	if contractScope := b.currentScope.ContractScope(); contractScope != nil {
		if ext := b.table.ScopeExts[contractScope.ID]; ext != nil {
			b.collectModifierDefinition(node, ext)
		}
	}
	prev := b.currentScope
	b.currentScope = modScope
	defer func() { b.currentScope = prev }()

	if md.Body != nil {
		return b.collectNode(md.Body)
	}
	return nil
}

func (b *Builder) collectStateVariable(node *parser.ASTNode) error {
	if node.StateVarDecl == nil {
		return nil
	}

	for _, v := range node.StateVarDecl.Variables {
		mutability := v.Mutability
		if mutability == "" {
			mutability = "mutable"
		}

		sym := &Symbol{
			Name:            v.Name,
			Kind:            KindStateVariable,
			SolcID:          v.ID,
			TypeName:        parser.TypeNameString(v.TypeName),
			Visibility:      v.Visibility,
			Mutability:      mutability,
			StorageLocation: LocationStorage, // State variable her zaman storage'da
			DeclarationNode: node,
		}
		if err := b.currentScope.Define(sym); err != nil {
			return err
		}
		b.table.AllSymbols = append(b.table.AllSymbols, sym)
	}
	return nil
}

func (b *Builder) collectLocalVariable(node *parser.ASTNode) error {
	if node.VarDeclStmt == nil {
		return nil
	}

	for _, declNode := range node.VarDeclStmt.Declarations {
		if declNode == nil {
			continue
		}
		// Tuple destructuring: (bool success, bytes memory data) = ...
		if declNode.NodeType != "VariableDeclaration" {
			continue
		}

		name := parser.VariableName(declNode)
		if name == "" {
			continue
		}

		sym := &Symbol{
			Name:            name,
			Kind:            KindLocalVariable,
			SolcID:          declNode.ID,
			StorageLocation: LocationStack,
			DeclarationNode: declNode,
		}
		if err := b.currentScope.Define(sym); err != nil {
			return err
		}
		b.table.AllSymbols = append(b.table.AllSymbols, sym)
	}
	return nil
}

func (b *Builder) collectBlock(node *parser.ASTNode) error {
	if node.Block == nil {
		return nil
	}

	blockScope := b.table.newScope(ScopeBlock, "", b.currentScope)
	prev := b.currentScope
	b.currentScope = blockScope
	defer func() { b.currentScope = prev }()

	for _, stmt := range node.Block.Statements {
		if err := b.collectNode(stmt); err != nil {
			return err
		}
	}
	return nil
}

// =========================================================
// PASS 2: Reference Resolver
// =========================================================

func (b *Builder) resolveReferences(unit *parser.SourceUnit) error {
	visitor := &referenceVisitor{builder: b}

	for _, node := range unit.Nodes {
		parser.WalkWithContext(node, parser.NewContextualVisitor(visitor))
	}
	return nil
}

// referenceVisitor Pass 2'deki AST gezginimiz.
type referenceVisitor struct {
	builder         *Builder
	currentScope    *Scope
	statementIndex  int
	externalCallIdx int
}

func (rv *referenceVisitor) HandleNode(ctx *parser.AnalysisContext, node *parser.ASTNode) bool {
	if node == nil {
		return false
	}

	switch node.NodeType {

	case "ContractDefinition":
		if node.ContractDef != nil {
			scope := rv.builder.findContractScope(node.ContractDef.Name)
			if scope != nil {
				rv.currentScope = scope
			}
		}
		return true

	case "FunctionDefinition":
		if node.FunctionDef != nil {
			scope := rv.builder.findFunctionScope(node.FunctionDef.Name, rv.currentScope)
			if scope != nil {
				rv.currentScope = scope
				rv.statementIndex = 0
				rv.externalCallIdx = -1
			}
		}
		return true

	case "ExpressionStatement":
		rv.statementIndex++

		if node.ExpressionStmt != nil && rv.isExternalCall(node.ExpressionStmt.Expression) {
			if rv.externalCallIdx < 0 {
				rv.externalCallIdx = rv.statementIndex
				if fnScope := rv.currentScope.FunctionScope(); fnScope != nil {
					fnScope.HasExternalCall = true
					fnScope.ExternalCallIndex = rv.statementIndex
				}
			}
		}

		if node.ExpressionStmt != nil {
			rv.trackAssignment(node.ExpressionStmt.Expression)
		}
		return true

	case "VariableDeclarationStatement":
		rv.statementIndex++

		// (bool success, ) = addr.call{value: x}("") pattern'i
		if node.VarDeclStmt != nil && rv.isExternalCall(node.VarDeclStmt.InitialValue) {
			if rv.externalCallIdx < 0 {
				rv.externalCallIdx = rv.statementIndex
				if fnScope := rv.currentScope.FunctionScope(); fnScope != nil {
					fnScope.HasExternalCall = true
					fnScope.ExternalCallIndex = rv.statementIndex
				}
			}
		}
		return true

	case "Identifier":
		rv.resolveIdentifier(node)
		return false

	case "Assignment":
		if node.Assignment != nil {
			rv.trackAssignmentNode(node.Assignment)
		}
		return false // Biz handle ettik, walker devam etmesin
	}

	return true
}

func (rv *referenceVisitor) resolveIdentifier(node *parser.ASTNode) {
	if node.Identifier == nil || rv.currentScope == nil {
		return
	}

	id := node.Identifier

	var sym *Symbol
	if id.ReferencedDeclaration != 0 {
		sym, _ = rv.currentScope.LookupByID(id.ReferencedDeclaration)
	}
	if sym == nil {
		sym, _ = rv.currentScope.Lookup(id.Name)
	}

	if sym == nil {
		return
	}

	afterCall := rv.externalCallIdx >= 0
	usage := Usage{
		Node:       node,
		ScopeID:    rv.currentScope.ID,
		InFunction: rv.currentFunctionName(),
		AfterCall:  afterCall,
	}
	sym.Reads = append(sym.Reads, usage)
}

// trackAssignment records write usage for assignments.
func (rv *referenceVisitor) trackAssignment(expr *parser.ASTNode) {
	if expr == nil || expr.NodeType != "Assignment" || expr.Assignment == nil {
		return
	}
	rv.trackAssignmentNode(expr.Assignment)
}

func (rv *referenceVisitor) trackAssignmentNode(assign *parser.Assignment) {
	if assign == nil {
		return
	}

	baseName := parser.BaseIdentifierName(assign.LeftHandSide)
	if baseName == "" {
		return
	}

	sym, _ := rv.currentScope.Lookup(baseName)
	if sym == nil {
		return
	}

	afterCall := rv.externalCallIdx >= 0

	if sym.IsStateVariable() && afterCall {
		sym.WrittenAfterExternalCall = true
	}

	usage := Usage{
		Node:       assign.LeftHandSide,
		ScopeID:    rv.currentScope.ID,
		InFunction: rv.currentFunctionName(),
		AfterCall:  afterCall,
	}
	sym.Writes = append(sym.Writes, usage)
}

func (rv *referenceVisitor) isExternalCall(node *parser.ASTNode) bool {
	if node == nil {
		return false
	}
	if node.NodeType == "FunctionCall" && node.FunctionCall != nil {
		expr := node.FunctionCall.Expression
		if expr != nil && expr.NodeType == "MemberAccess" && expr.MemberAccess != nil {
			switch expr.MemberAccess.MemberName {
			case "call", "delegatecall", "staticcall", "transfer", "send":
				return true
			}
		}
	}
	return false
}

func (rv *referenceVisitor) currentFunctionName() string {
	if rv.currentScope == nil {
		return ""
	}
	fnScope := rv.currentScope.FunctionScope()
	if fnScope == nil {
		return ""
	}
	return fnScope.Name
}

func (b *Builder) findContractScope(name string) *Scope {
	for _, scope := range b.table.AllScopes {
		if scope.Kind == ScopeContract && scope.Name == name {
			return scope
		}
	}
	return nil
}

func (b *Builder) findFunctionScope(name string, parent *Scope) *Scope {
	if parent == nil {
		return nil
	}
	for _, child := range parent.Children {
		if child.Kind == ScopeFunction && child.Name == name {
			return child
		}
	}
	return nil
}

// =========================================================
// HELPER FUNCTIONS & MISSING TYPES
// =========================================================

func parseStorageLocation(loc string) StorageLocation {
	switch strings.TrimSpace(loc) {
	case "storage":
		return LocationStorage
	case "memory":
		return LocationMemory
	case "calldata":
		return LocationCalldata
	default:
		return LocationStack
	}
}

// typeNameString is kept as a compatibility wrapper for older builder code.
// New code should call parser.TypeNameString directly.
func typeNameString(node *parser.ASTNode) string {
	return parser.TypeNameString(node)
}

// extractVarName is kept as a compatibility wrapper for older builder code.
// New code should call parser.VariableName directly.
func extractVarName(node *parser.ASTNode) string {
	return parser.VariableName(node)
}

// extractBaseIdentifierName is kept as a compatibility wrapper for older builder code.
// New code should call parser.BaseIdentifierName directly.
func extractBaseIdentifierName(node *parser.ASTNode) string {
	return parser.BaseIdentifierName(node)
}
