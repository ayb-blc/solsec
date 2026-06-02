package symboltable

type ModifierInfo struct {
	Name       string
	BodyNodeID int
}

type InheritanceInfo struct {
	DirectParents []string
	AllAncestors  map[string]bool
}

type ScopeExtension struct {
	Modifiers map[string]*ModifierInfo

	AppliedModifiers []string

	Inheritance *InheritanceInfo

	StatementOrder map[int]int
}

type ScopeWithExt struct {
	*Scope
	Ext ScopeExtension
}

func newScopeWithExt(id ScopeID, kind ScopeKind, name string, parent *Scope) *ScopeWithExt {
	return newScopeExtension(NewScope(id, kind, name, parent))
}

func newScopeExtension(scope *Scope) *ScopeWithExt {
	return &ScopeWithExt{
		Scope: scope,
		Ext: ScopeExtension{
			Modifiers:      make(map[string]*ModifierInfo),
			StatementOrder: make(map[int]int),
			Inheritance:    &InheritanceInfo{AllAncestors: make(map[string]bool)},
		},
	}
}
