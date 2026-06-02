package callgraph

import (
	"fmt"
	"strings"

	"github.com/ayb-blc/solsec/internal/parser"
)

type CallKind int

const (
	CallInternal     CallKind = iota
	CallExternal              // otherContract.foo()
	CallDelegatecall          // addr.delegatecall(...)
	CallStaticall
	CallLibrary // LibraryName.foo(a, b)
	CallVirtual
)

func (k CallKind) String() string {
	switch k {
	case CallInternal:
		return "internal"
	case CallExternal:
		return "external"
	case CallDelegatecall:
		return "delegatecall"
	case CallStaticall:
		return "staticcall"
	case CallLibrary:
		return "library"
	case CallVirtual:
		return "virtual"
	default:
		return "unknown"
	}
}

type FunctionID string

func NewFunctionID(contract, function string) FunctionID {
	return FunctionID(fmt.Sprintf("%s.%s", contract, function))
}

func (id FunctionID) Contract() string {
	parts := strings.SplitN(string(id), ".", 2)
	if len(parts) == 2 {
		return parts[0]
	}
	return ""
}

func (id FunctionID) Function() string {
	parts := strings.SplitN(string(id), ".", 2)
	if len(parts) == 2 {
		return parts[1]
	}
	return string(id)
}

func (id FunctionID) String() string { return string(id) }

type CallSite struct {
	Caller FunctionID

	// Belirsizse (virtual call) empty string
	Callee FunctionID

	Kind CallKind

	// CallNode AST'deki FunctionCall node'u
	CallNode *parser.ASTNode

	ArgumentNodes []*parser.ASTNode

	// Virtual call'larda false olabilir
	IsResolved bool
}

type FunctionNode struct {
	ID         FunctionID
	Name       string
	Contract   string
	Visibility string // public, external, internal, private
	Mutability string // pure, view, payable, nonpayable
	IsModifier bool
	ASTNode    *parser.ASTNode

	Callers []*CallSite

	Callees []*CallSite

	// --- Security Properties ---

	HasExternalCall bool

	HasStateWrite bool

	IsReachableFromExternal bool

	TransitiveExternalCall bool

	TransitiveStateWrite bool

	// Depth is the distance from the entry point in the call graph.
	Depth int
}

type CallGraph struct {
	Nodes map[FunctionID]*FunctionNode

	EntryPoints []*FunctionNode

	CallSites []*CallSite

	Cycles [][]FunctionID
}

func NewCallGraph() *CallGraph {
	return &CallGraph{
		Nodes: make(map[FunctionID]*FunctionNode),
	}
}

func (cg *CallGraph) AddNode(node *FunctionNode) {
	cg.Nodes[node.ID] = node
	if node.Visibility == "public" || node.Visibility == "external" {
		cg.EntryPoints = append(cg.EntryPoints, node)
	}
}

func (cg *CallGraph) AddCallSite(cs *CallSite) {
	cg.CallSites = append(cg.CallSites, cs)

	// Add the edge as a callee of the caller node.
	if caller, ok := cg.Nodes[cs.Caller]; ok {
		caller.Callees = append(caller.Callees, cs)
	}

	// Add the edge as a caller of the callee node.
	if cs.IsResolved {
		if callee, ok := cg.Nodes[cs.Callee]; ok {
			callee.Callers = append(callee.Callers, cs)
		}
	}
}

func (cg *CallGraph) TransitiveCallers(id FunctionID) []*FunctionNode {
	visited := make(map[FunctionID]bool)
	var result []*FunctionNode
	cg.transitiveCallersHelper(id, visited, &result)
	return result
}

func (cg *CallGraph) transitiveCallersHelper(
	id FunctionID,
	visited map[FunctionID]bool,
	result *[]*FunctionNode,
) {
	if visited[id] {
		return
	}
	visited[id] = true

	node, ok := cg.Nodes[id]
	if !ok {
		return
	}

	for _, cs := range node.Callers {
		if callerNode, exists := cg.Nodes[cs.Caller]; exists {
			*result = append(*result, callerNode)
			cg.transitiveCallersHelper(cs.Caller, visited, result)
		}
	}
}

func (cg *CallGraph) TransitiveCallees(id FunctionID) []*FunctionNode {
	visited := make(map[FunctionID]bool)
	var result []*FunctionNode
	cg.transitiveCalleesHelper(id, visited, &result)
	return result
}

func (cg *CallGraph) transitiveCalleesHelper(
	id FunctionID,
	visited map[FunctionID]bool,
	result *[]*FunctionNode,
) {
	if visited[id] {
		return
	}
	visited[id] = true

	node, ok := cg.Nodes[id]
	if !ok {
		return
	}

	for _, cs := range node.Callees {
		if !cs.IsResolved {
			continue
		}
		if calleeNode, exists := cg.Nodes[cs.Callee]; exists {
			*result = append(*result, calleeNode)
			cg.transitiveCalleesHelper(cs.Callee, visited, result)
		}
	}
}
