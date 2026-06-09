// internal/inheritancegraph/graph.go

package inheritancegraph

import "strings"

// ContractKind distinguishes between the four Solidity contract types.
type ContractKind uint8

const (
	KindContract  ContractKind = iota // contract Foo
	KindInterface                     // interface IFoo
	KindLibrary                       // library SafeMath
	KindAbstract                      // abstract contract Foo
)

func (k ContractKind) String() string {
	switch k {
	case KindInterface:
		return "interface"
	case KindLibrary:
		return "library"
	case KindAbstract:
		return "abstract"
	default:
		return "contract"
	}
}

// ContractNode represents a single Solidity contract in the project graph.
type ContractNode struct {
	Name     string
	Filepath string
	Kind     ContractKind

	// Direct parents in declaration order.
	// "contract A is B, C" means Parents = [B, C].
	Parents []*ContractNode

	Children []*ContractNode

	// Functions declared in this contract (not inherited).
	// Key is function name; for overloaded functions, only the
	// last-seen definition is kept (sufficient for modifier analysis).
	Functions map[string]*FunctionNode

	// Modifiers declared in this contract.
	Modifiers map[string]*ModifierDef

	// State variables declared at contract scope.
	StateVars []StateVar

	// Raw source for detectors that need body scanning.
	SourceLines []string
}

func (c *ContractNode) IsInterface() bool { return c.Kind == KindInterface }

func (c *ContractNode) IsAbstract() bool { return c.Kind == KindAbstract }

func (c *ContractNode) IsLibrary() bool { return c.Kind == KindLibrary }

func (c *ContractNode) HasChildren() bool { return len(c.Children) > 0 }

// FunctionNode represents a function declared inside a ContractNode.
type FunctionNode struct {
	Name       string
	Signature  string
	Params     string
	Modifiers  []string
	Visibility string
	Mutability string
	Returns    string
	IsVirtual  bool
	IsOverride bool
	LineNumber int

	// Body source lines (between { and matching }).
	BodyLines []string

	Contract *ContractNode

	// Populated by Graph.EnrichFunctions.
	Canonical         string
	Selector          [4]byte
	NormalizedParams  []ParamType
	NormalizedReturns []ParamType
}

// HasAccessControl reports whether the function has any access control modifier.
func (fn *FunctionNode) HasAccessControl() bool {
	for _, m := range fn.Modifiers {
		if looksLikeAccessControl(m) {
			return true
		}
	}
	return false
}

func (fn *FunctionNode) ModifierNames() string {
	return strings.Join(fn.Modifiers, ", ")
}

func (fn *FunctionNode) IsViewOrPure() bool {
	return fn.Mutability == "view" || fn.Mutability == "pure"
}

// StateVar represents a state variable at contract scope.
type StateVar struct {
	Name        string
	TypeName    string
	Visibility  string // public | private | internal
	IsConstant  bool
	IsImmutable bool
	LineNumber  int
}

// Graph is the project-wide inheritance graph.
// It is built once at scan start and shared across all detectors.
type Graph struct {
	// Canonical index: "filepath::ContractName"
	contracts map[string]*ContractNode

	// Name index: ContractName to all nodes with that name.
	// Multiple files can define contracts with the same name.
	byName map[string][]*ContractNode

	// File index: filepath to contracts defined in that file.
	byFile map[string][]*ContractNode
}

// NewGraph returns an empty Graph.
func NewGraph() *Graph {
	return &Graph{
		contracts: make(map[string]*ContractNode),
		byName:    make(map[string][]*ContractNode),
		byFile:    make(map[string][]*ContractNode),
	}
}

func (g *Graph) contractKey(filepath, name string) string {
	return filepath + "::" + name
}

func (g *Graph) addNode(c *ContractNode) {
	key := g.contractKey(c.Filepath, c.Name)
	g.contracts[key] = c
	g.byName[c.Name] = append(g.byName[c.Name], c)
	g.byFile[c.Filepath] = append(g.byFile[c.Filepath], c)
}

// ContractsInFile returns all contracts defined in the given source file.
func (g *Graph) ContractsInFile(filepath string) []*ContractNode {
	return g.byFile[filepath]
}

// FindByName returns all contracts with the given name across the project.
// Most codebases define each name once, but name collisions are possible.
func (g *Graph) FindByName(name string) []*ContractNode {
	return g.byName[name]
}

// FindOne returns the first contract found with the given name,
// or nil if none exists. Use when name uniqueness can be assumed.
func (g *Graph) FindOne(name string) *ContractNode {
	if nodes := g.byName[name]; len(nodes) > 0 {
		return nodes[0]
	}
	return nil
}

// AllContracts returns every contract node in the graph.
func (g *Graph) AllContracts() []*ContractNode {
	out := make([]*ContractNode, 0, len(g.contracts))
	for _, c := range g.contracts {
		out = append(out, c)
	}
	return out
}

// Size reports the number of contracts in the graph.
func (g *Graph) Size() int { return len(g.contracts) }

// looksLikeAccessControl is a lightweight heuristic used by FunctionNode.
func looksLikeAccessControl(modifier string) bool {
	m := strings.ToLower(modifier)
	prefixes := []string{
		"onlyowner", "onlyadmin", "onlyrole", "onlyoperator",
		"onlygovernor", "onlyguardian", "onlybridge",
		"onlypool", "ifadmin", "restricted", "requiresauth",
		"auth", "protected",
	}
	for _, p := range prefixes {
		if strings.HasPrefix(m, p) || strings.HasPrefix(m, "only") {
			return true
		}
	}
	return false
}
