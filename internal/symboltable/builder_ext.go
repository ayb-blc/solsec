package symboltable

import (
	"github.com/ayb-blc/solsec/internal/parser"
)

//
//   scopeExts    map[ScopeID]*ScopeWithExt

func (b *Builder) collectContractInheritance(node *parser.ASTNode, scope *ScopeWithExt) {
	if node.ContractDef == nil {
		return
	}
	cd := node.ContractDef

	info := scope.Ext.Inheritance
	for _, base := range cd.BaseContracts {
		parentName := base.BaseName.Name
		if parentName == "" {
			continue
		}
		info.DirectParents = append(info.DirectParents, parentName)
	}
}

func (b *Builder) resolveAllAncestors(contractScopes map[string]*ScopeWithExt) {
	visited := make(map[string]bool)

	var resolve func(name string)
	resolve = func(name string) {
		if visited[name] {
			return
		}
		visited[name] = true

		scope, ok := contractScopes[name]
		if !ok {
			return
		}

		info := scope.Ext.Inheritance
		for _, parent := range info.DirectParents {
			resolve(parent)

			if parentScope, exists := contractScopes[parent]; exists {
				for ancestor := range parentScope.Ext.Inheritance.AllAncestors {
					info.AllAncestors[ancestor] = true
				}
			}
			info.AllAncestors[parent] = true
		}
	}

	for name := range contractScopes {
		resolve(name)
	}
}

func (b *Builder) collectFunctionModifiers(
	fd *parser.FunctionDefinition,
	fnScope *ScopeWithExt,
) {
	for _, modNode := range fd.Modifiers {
		if modNode.ModifierInvoc == nil {
			continue
		}
		name := modNode.ModifierInvoc.ModifierName.Name
		if name != "" {
			fnScope.Ext.AppliedModifiers = append(fnScope.Ext.AppliedModifiers, name)
		}
	}
}

func (b *Builder) collectModifierDefinition(
	node *parser.ASTNode,
	contractScope *ScopeWithExt,
) {
	if node.ModifierDef == nil {
		return
	}
	md := node.ModifierDef
	contractScope.Ext.Modifiers[md.Name] = &ModifierInfo{
		Name:       md.Name,
		BodyNodeID: node.ID,
	}
}

func buildStatementOrder(block *parser.Block) map[int]int {
	order := make(map[int]int)
	if block == nil {
		return order
	}
	for i, stmt := range block.Statements {
		if stmt != nil {
			fillNodeOrder(stmt, i, order)
		}
	}
	return order
}

// fillNodeOrder maps every node under a statement to that statement's index.
// Usage nodes are often identifiers or member-access expressions, not the
// top-level statement node, so taint ordering must recognize the full subtree.
func fillNodeOrder(node *parser.ASTNode, parentIdx int, order map[int]int) {
	if node == nil {
		return
	}
	parser.Walk(node, parser.VisitorFunc(func(child *parser.ASTNode) bool {
		if child != nil && child.ID != 0 {
			if _, exists := order[child.ID]; !exists {
				order[child.ID] = parentIdx
			}
		}
		return true
	}))
}
