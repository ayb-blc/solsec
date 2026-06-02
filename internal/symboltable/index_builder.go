package symboltable

import "github.com/ayb-blc/solsec/internal/parser"

type IndexBuilder struct {
	indexDB *IndexDB
}

func NewIndexBuilder() *IndexBuilder {
	return &IndexBuilder{indexDB: NewIndexDB()}
}

func (ib *IndexBuilder) RegisterFunction(
	fd *parser.FunctionDefinition,
	fnScopeID ScopeID,
) {
	if fd.Body == nil || fd.Body.Block == nil {
		return
	}
	ib.indexDB.Register(fd.Body.Block, fnScopeID, 0, nil)
}

func (ib *IndexBuilder) IndexDB() *IndexDB {
	return ib.indexDB
}

func BuildWithIndex(
	unit *parser.SourceUnit,
	srcMap *parser.SourceMap,
) (*SymbolTable, *IndexDB, error) {
	st, err := Build(unit, srcMap)
	if err != nil {
		return nil, nil, err
	}
	ib := NewIndexBuilder()

	registerFunctionIndexes(unit, st, ib)
	return st, ib.IndexDB(), nil
}

func registerFunctionIndexes(unit *parser.SourceUnit, st *SymbolTable, ib *IndexBuilder) {
	if unit == nil || st == nil || ib == nil {
		return
	}
	for _, node := range unit.Nodes {
		registerFunctionIndexesInNode(node, st, ib)
	}
}

func registerFunctionIndexesInNode(node *parser.ASTNode, st *SymbolTable, ib *IndexBuilder) {
	if node == nil {
		return
	}
	switch node.NodeType {
	case "ContractDefinition":
		if node.ContractDef == nil {
			return
		}
		for _, child := range node.ContractDef.Nodes {
			registerFunctionIndexesInNode(child, st, ib)
		}
	case "FunctionDefinition":
		if node.FunctionDef == nil {
			return
		}
		if scope := findFunctionScope(st, node.FunctionDef.Name); scope != nil {
			ib.RegisterFunction(node.FunctionDef, scope.ID)
		}
	}
}

func findFunctionScope(st *SymbolTable, name string) *Scope {
	for _, scope := range st.AllScopes {
		if scope.Kind == ScopeFunction && scope.Name == name {
			return scope
		}
	}
	return nil
}
