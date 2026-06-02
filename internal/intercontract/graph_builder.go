package intercontract

import (
	"strings"

	"github.com/ayb-blc/solsec/internal/parser"
)

type CrossContractGraphBuilder struct {
	project *Project
}

func NewCrossContractGraphBuilder(project *Project) *CrossContractGraphBuilder {
	return &CrossContractGraphBuilder{project: project}
}

func (b *CrossContractGraphBuilder) Build() *CrossContractCallGraph {
	graph := NewCrossContractCallGraph()
	if b == nil || b.project == nil {
		return graph
	}

	for _, c := range b.project.AllContracts() {
		for _, fn := range c.Contract.Functions {
			name := normalizeFunctionName(fn.Name, "")
			node := &CrossContractNode{
				ID:           NewGlobalFunctionID(c.Contract.Name, name),
				ContractName: c.Contract.Name,
				FunctionName: name,
				Filepath:     c.Filepath,
				Line:         fn.Line,
				Visibility:   fn.Visibility,
				Mutability:   fn.Mutability,
				Modifiers:    append([]string(nil), fn.Modifiers...),
			}
			node.HasStateWrite = b.functionWritesState(c.Contract, fn)
			graph.AddNode(node)
		}
	}

	for _, c := range b.project.AllContracts() {
		for _, fn := range c.Contract.Functions {
			callerID := NewGlobalFunctionID(c.Contract.Name, normalizeFunctionName(fn.Name, ""))
			for _, call := range b.functionCalls(fn) {
				if call.kind == CrossCallLowLevel || call.kind == CrossCallDelegatecall {
					graph.AddUnresolved(&UnresolvedCrossCall{
						Caller:       callerID,
						Target:       call.receiver,
						FunctionName: call.name,
						CallKind:     call.kind,
						CallLine:     call.line,
					})
					continue
				}

				targets := b.resolveCallTargets(c.Contract.Name, call.name)
				if len(targets) == 0 {
					graph.AddUnresolved(&UnresolvedCrossCall{
						Caller:       callerID,
						Target:       call.receiver,
						FunctionName: call.name,
						CallKind:     call.kind,
						CallLine:     call.line,
					})
					continue
				}
				for _, target := range targets {
					graph.AddEdge(&CrossContractEdge{
						Caller:   callerID,
						Callee:   target,
						CallKind: call.kind,
						CallLine: call.line,
					})
				}
			}
		}
	}

	graph.ComputeTransitiveFlags()
	return graph
}

type discoveredCall struct {
	name     string
	receiver string
	kind     CrossCallKind
	line     int
}

func (b *CrossContractGraphBuilder) functionCalls(fn *parser.UnifiedFunction) []discoveredCall {
	var calls []discoveredCall
	node, _ := fn.Raw.(*parser.ASTNode)
	if node == nil || node.FunctionDef == nil || node.FunctionDef.Body == nil {
		return calls
	}

	parser.Walk(node.FunctionDef.Body, parser.VisitorFunc(func(n *parser.ASTNode) bool {
		if n == nil || n.NodeType != "FunctionCall" || n.FunctionCall == nil {
			return true
		}
		call := callFromExpression(n.FunctionCall.Expression)
		if call.name == "" {
			return true
		}
		call.line = nodeLine(n)
		calls = append(calls, call)
		return true
	}))
	return calls
}

func callFromExpression(expr *parser.ASTNode) discoveredCall {
	if expr == nil {
		return discoveredCall{}
	}
	switch expr.NodeType {
	case "MemberAccess":
		if expr.MemberAccess == nil {
			return discoveredCall{}
		}
		name := expr.MemberAccess.MemberName
		receiver := parser.ExtractFullName(expr.MemberAccess.Expression)
		kind := CrossCallExternal
		switch name {
		case "call", "staticcall":
			kind = CrossCallLowLevel
		case "delegatecall":
			kind = CrossCallDelegatecall
		}
		return discoveredCall{name: name, receiver: receiver, kind: kind}
	case "Identifier":
		if expr.Identifier == nil {
			return discoveredCall{}
		}
		return discoveredCall{name: expr.Identifier.Name, kind: CrossCallInternal}
	}
	return discoveredCall{}
}

func (b *CrossContractGraphBuilder) resolveCallTargets(currentContract, functionName string) []GlobalFunctionID {
	var targets []GlobalFunctionID
	for _, c := range b.project.AllContracts() {
		for _, fn := range c.Contract.Functions {
			name := normalizeFunctionName(fn.Name, "")
			if name != functionName {
				continue
			}
			if c.Contract.Name != currentContract && !isExternalVisibility(fn.Visibility) {
				continue
			}
			kind := CrossCallInternal
			if c.Contract.Name != currentContract {
				kind = CrossCallExternal
			}
			_ = kind
			targets = append(targets, NewGlobalFunctionID(c.Contract.Name, name))
		}
	}
	return targets
}

func (b *CrossContractGraphBuilder) functionWritesState(contract *parser.UnifiedContract, fn *parser.UnifiedFunction) bool {
	if !isStateChangingMutability(fn.Mutability) {
		return false
	}
	stateVars := make(map[string]struct{}, len(contract.StateVars))
	for _, v := range contract.StateVars {
		stateVars[v.Name] = struct{}{}
	}
	if len(stateVars) == 0 {
		return false
	}

	node, _ := fn.Raw.(*parser.ASTNode)
	if node == nil || node.FunctionDef == nil || node.FunctionDef.Body == nil {
		for _, stmt := range fn.Body {
			if stmt.WritesState {
				return true
			}
		}
		return false
	}

	writes := false
	parser.Walk(node.FunctionDef.Body, parser.VisitorFunc(func(n *parser.ASTNode) bool {
		if n == nil || n.Assignment == nil {
			return true
		}
		base := parser.ExtractBaseName(n.Assignment.LeftHandSide)
		if _, ok := stateVars[base]; ok {
			writes = true
			return false
		}
		return true
	}))
	return writes
}

func nodeLine(node *parser.ASTNode) int {
	if node == nil {
		return 0
	}
	return 0
}

func isExternalVisibility(visibility string) bool {
	return visibility == parser.VisibilityPublic || visibility == parser.VisibilityExternal
}

func isStateChangingMutability(mutability string) bool {
	return mutability == "" ||
		mutability == parser.MutabilityNonpayable ||
		mutability == parser.MutabilityPayable
}

func normalizeFunctionName(name, kind string) string {
	if name != "" {
		return name
	}
	switch strings.ToLower(kind) {
	case "constructor":
		return "<constructor>"
	case "fallback":
		return "<fallback>"
	case "receive":
		return "<receive>"
	default:
		return "<anonymous>"
	}
}
