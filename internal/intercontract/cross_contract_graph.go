package intercontract

import (
	"fmt"
	"strings"
)

// GlobalFunctionID uniquely identifies a function in a project-level graph.
type GlobalFunctionID string

func NewGlobalFunctionID(contractName, functionName string) GlobalFunctionID {
	return GlobalFunctionID(contractName + "." + functionName)
}

func (id GlobalFunctionID) String() string { return string(id) }

func (id GlobalFunctionID) Contract() string {
	parts := strings.SplitN(string(id), ".", 2)
	if len(parts) == 0 {
		return ""
	}
	return parts[0]
}

func (id GlobalFunctionID) Function() string {
	parts := strings.SplitN(string(id), ".", 2)
	if len(parts) != 2 {
		return ""
	}
	return parts[1]
}

// CrossCallKind describes how one function reaches another.
type CrossCallKind string

const (
	CrossCallInternal     CrossCallKind = "internal"
	CrossCallExternal     CrossCallKind = "external"
	CrossCallLowLevel     CrossCallKind = "low-level"
	CrossCallDelegatecall CrossCallKind = "delegatecall"
)

func (k CrossCallKind) IsExternal() bool {
	return k == CrossCallExternal || k == CrossCallLowLevel || k == CrossCallDelegatecall
}

// CrossContractCallGraph is a project-level function graph.
type CrossContractCallGraph struct {
	Nodes           map[GlobalFunctionID]*CrossContractNode
	EntryPoints     []*CrossContractNode
	UnresolvedCalls []*UnresolvedCrossCall
}

func NewCrossContractCallGraph() *CrossContractCallGraph {
	return &CrossContractCallGraph{
		Nodes: make(map[GlobalFunctionID]*CrossContractNode),
	}
}

type CrossContractNode struct {
	ID                      GlobalFunctionID
	ContractName            string
	FunctionName            string
	Filepath                string
	Line                    int
	Visibility              string
	Mutability              string
	Modifiers               []string
	Callees                 []*CrossContractEdge
	Callers                 []*CrossContractEdge
	HasExternalCall         bool
	TransitiveExternalCall  bool
	HasStateWrite           bool
	TransitiveStateWrite    bool
	IsReachableFromExternal bool
}

type CrossContractEdge struct {
	Caller   GlobalFunctionID
	Callee   GlobalFunctionID
	CallKind CrossCallKind
	CallLine int
}

type UnresolvedCrossCall struct {
	Caller       GlobalFunctionID
	Target       string
	FunctionName string
	CallKind     CrossCallKind
	CallLine     int
}

func (g *CrossContractCallGraph) AddNode(node *CrossContractNode) {
	if node == nil {
		return
	}
	g.Nodes[node.ID] = node
	if isExternalVisibility(node.Visibility) {
		node.IsReachableFromExternal = true
		g.EntryPoints = append(g.EntryPoints, node)
	}
}

func (g *CrossContractCallGraph) AddEdge(edge *CrossContractEdge) {
	if edge == nil {
		return
	}
	caller, ok := g.Nodes[edge.Caller]
	if !ok {
		return
	}
	caller.Callees = append(caller.Callees, edge)
	if callee, ok := g.Nodes[edge.Callee]; ok {
		callee.Callers = append(callee.Callers, edge)
	}
	if edge.CallKind.IsExternal() {
		caller.HasExternalCall = true
	}
}

func (g *CrossContractCallGraph) AddUnresolved(call *UnresolvedCrossCall) {
	if call == nil {
		return
	}
	g.UnresolvedCalls = append(g.UnresolvedCalls, call)
	if node, ok := g.Nodes[call.Caller]; ok && call.CallKind.IsExternal() {
		node.HasExternalCall = true
	}
}

func (g *CrossContractCallGraph) ComputeTransitiveFlags() {
	changed := true
	for changed {
		changed = false
		for _, node := range g.Nodes {
			for _, edge := range node.Callees {
				callee := g.Nodes[edge.Callee]
				if callee == nil {
					continue
				}
				if (callee.HasExternalCall || callee.TransitiveExternalCall) && !node.TransitiveExternalCall {
					node.TransitiveExternalCall = true
					changed = true
				}
				if (callee.HasStateWrite || callee.TransitiveStateWrite) && !node.TransitiveStateWrite {
					node.TransitiveStateWrite = true
					changed = true
				}
			}
		}
	}
}

func (k CrossCallKind) String() string {
	if k == "" {
		return "unknown"
	}
	return string(k)
}

func (id GlobalFunctionID) GoString() string {
	return fmt.Sprintf("%q", string(id))
}
