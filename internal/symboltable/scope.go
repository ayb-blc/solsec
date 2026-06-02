package symboltable

import "fmt"

type ScopeID int

type ScopeKind int

const (
	ScopeGlobal   ScopeKind = iota
	ScopeContract           // Contract body
	ScopeFunction
	ScopeModifier // Modifier body
	ScopeBlock    // if/for/while body or anonymous block
)

func (k ScopeKind) String() string {
	switch k {
	case ScopeGlobal:
		return "global"
	case ScopeContract:
		return "contract"
	case ScopeFunction:
		return "function"
	case ScopeModifier:
		return "modifier"
	case ScopeBlock:
		return "block"
	default:
		return "unknown"
	}
}

// Scope{kind: Contract, name: "Vault"}
type Scope struct {
	ID       ScopeID
	Kind     ScopeKind
	Name     string
	Parent   *Scope
	Children []*Scope

	Symbols map[string]*Symbol

	SymbolsByID map[int]*Symbol

	HasExternalCall bool

	ExternalCallIndex int
}

func NewScope(id ScopeID, kind ScopeKind, name string, parent *Scope) *Scope {
	s := &Scope{
		ID:                id,
		Kind:              kind,
		Name:              name,
		Parent:            parent,
		Symbols:           make(map[string]*Symbol),
		SymbolsByID:       make(map[int]*Symbol),
		ExternalCallIndex: -1,
	}
	if parent != nil {
		parent.Children = append(parent.Children, s)
	}
	return s
}

func (s *Scope) Define(sym *Symbol) error {
	if existing, ok := s.Symbols[sym.Name]; ok {
		if existing.Kind == KindStateVariable && sym.Kind == KindLocalVariable {
		}
	}
	s.Symbols[sym.Name] = sym
	if sym.SolcID != 0 {
		s.SymbolsByID[sym.SolcID] = sym
	}
	sym.DeclaredInScope = s
	return nil
}

// Bulunamazsa: nil, nil
func (s *Scope) Lookup(name string) (*Symbol, *Scope) {
	current := s
	for current != nil {
		if sym, ok := current.Symbols[name]; ok {
			return sym, current
		}
		current = current.Parent
	}
	return nil, nil
}

func (s *Scope) LookupByID(id int) (*Symbol, *Scope) {
	current := s
	for current != nil {
		if sym, ok := current.SymbolsByID[id]; ok {
			return sym, current
		}
		current = current.Parent
	}
	return nil, nil
}

func (s *Scope) IsDescendantOf(kind ScopeKind) bool {
	current := s
	for current != nil {
		if current.Kind == kind {
			return true
		}
		current = current.Parent
	}
	return false
}

func (s *Scope) ContractScope() *Scope {
	current := s
	for current != nil {
		if current.Kind == ScopeContract {
			return current
		}
		current = current.Parent
	}
	return nil
}

func (s *Scope) FunctionScope() *Scope {
	current := s
	for current != nil {
		if current.Kind == ScopeFunction {
			return current
		}
		current = current.Parent
	}
	return nil
}

func (s *Scope) String() string {
	return fmt.Sprintf("Scope{kind=%s, name=%q, symbols=%d}", s.Kind, s.Name, len(s.Symbols))
}
