package symboltable

func (st *SymbolTable) StateVariablesWrittenAfterCall() []*Symbol {
	var result []*Symbol
	for _, sym := range st.AllSymbols {
		if sym.IsStateVariable() && sym.WrittenAfterExternalCall {
			result = append(result, sym)
		}
	}
	return result
}

func (st *SymbolTable) FindFunctionScope(id ScopeID) *Scope {
	scope, ok := st.AllScopes[id]
	if !ok {
		return nil
	}
	return scope.FunctionScope()
}

func (st *SymbolTable) ContractInheritsFrom(contractName, parentName string) bool {
	if st.ContractScopes != nil {
		if scope, ok := st.ContractScopes[contractName]; ok && scope.Ext.Inheritance != nil {
			if scope.Ext.Inheritance.AllAncestors[parentName] {
				return true
			}
			for _, parent := range scope.Ext.Inheritance.DirectParents {
				if parent == parentName {
					return true
				}
			}
		}
	}

	if st.sourceUnit != nil {
		for _, node := range st.sourceUnit.Nodes {
			if node == nil || node.ContractDef == nil || node.ContractDef.Name != contractName {
				continue
			}
			for _, base := range node.ContractDef.BaseContracts {
				parent := base.BaseName.Name
				if parent == parentName || st.ContractInheritsFrom(parent, parentName) {
					return true
				}
			}
		}
	}
	return false
}

func (st *SymbolTable) FunctionHasModifier(fnName, contractName, modifierName string) bool {
	for _, scope := range st.AllScopes {
		if scope.Kind == ScopeFunction && scope.Name == fnName {
			if contractScope := scope.ContractScope(); contractScope != nil {
				if contractScope.Name != contractName {
					continue
				}
			}
			if ext := st.FunctionScopeExts[scope.ID]; ext != nil {
				for _, modifier := range ext.Ext.AppliedModifiers {
					if modifier == modifierName {
						return true
					}
				}
			}
		}
	}

	for _, sym := range st.AllSymbols {
		if sym.Kind != KindFunction || sym.Name != fnName {
			continue
		}
		if sym.DeclaredInScope == nil {
			continue
		}
		contractScope := sym.DeclaredInScope.ContractScope()
		if contractScope == nil || contractScope.Name != contractName {
			continue
		}
		if sym.DeclarationNode == nil || sym.DeclarationNode.FunctionDef == nil {
			continue
		}
		for _, modNode := range sym.DeclarationNode.FunctionDef.Modifiers {
			if modNode.ModifierInvoc != nil &&
				modNode.ModifierInvoc.ModifierName.Name == modifierName {
				return true
			}
		}
	}
	return false
}

func (st *SymbolTable) UserControlledSymbols() []*Symbol {
	var result []*Symbol
	for _, sym := range st.AllSymbols {
		if sym.IsUserControlled {
			result = append(result, sym)
		}
	}
	return result
}

func (st *SymbolTable) UnusedStateVariables() []*Symbol {
	var result []*Symbol
	for _, sym := range st.AllSymbols {
		if sym.IsStateVariable() && sym.ReadCount() == 0 && sym.WriteCount() == 0 {
			result = append(result, sym)
		}
	}
	return result
}

func (st *SymbolTable) WriteOnlyStateVariables() []*Symbol {
	var result []*Symbol
	for _, sym := range st.AllSymbols {
		if sym.IsStateVariable() && sym.ReadCount() == 0 && sym.WriteCount() > 0 {
			result = append(result, sym)
		}
	}
	return result
}

func (st *SymbolTable) findContractScopeByName(name string) *Scope {
	for _, scope := range st.AllScopes {
		if scope.Kind == ScopeContract && scope.Name == name {
			return scope
		}
	}
	return nil
}
