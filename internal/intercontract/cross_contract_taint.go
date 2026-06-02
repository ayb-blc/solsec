package intercontract

import (
	"github.com/ayb-blc/solsec/internal/analyzer"
	"github.com/ayb-blc/solsec/internal/parser"
	"github.com/ayb-blc/solsec/internal/taint"
)

// CrossContractTaintEngine performs taint analysis across contract boundaries.
type CrossContractTaintEngine struct {
	graph   *CrossContractCallGraph
	project *Project

	taintState map[GlobalFunctionID]*CrossContractTaintState

	flows []CrossContractTaintFlow
}

// CrossContractTaintState stores taint state for one cross-contract function.
type CrossContractTaintState struct {
	TaintedParams map[int]taint.TaintLabel

	ReturnTainted bool
	ReturnLabel   taint.TaintLabel

	TaintedStorage map[string]taint.TaintLabel
}

type CrossContractTaintFlow struct {
	SourceFunction GlobalFunctionID

	SourceLabel taint.TaintLabel

	Crossings []ContractBoundaryCrossing

	SinkFunction GlobalFunctionID

	SinkKind taint.SinkKind

	// Severity bu flow'un risk seviyesi
	Severity analyzer.Severity
}

type ContractBoundaryCrossing struct {
	FromContract string
	ToContract   string
	ViaFunction  string
	CallKind     CrossCallKind
	Line         int
}

func NewCrossContractTaintEngine(
	graph *CrossContractCallGraph,
	project *Project,
) *CrossContractTaintEngine {
	return &CrossContractTaintEngine{
		graph:      graph,
		project:    project,
		taintState: make(map[GlobalFunctionID]*CrossContractTaintState),
	}
}

// 1. Entry point'lerde taint'i seed et (msg.sender, msg.value, calldata)
// 2. Her entry point'ten DFS ile taint'i yay
func (e *CrossContractTaintEngine) Analyze() []CrossContractTaintFlow {
	for _, entry := range e.graph.EntryPoints {
		initialState := e.seedEntryPoint(entry)
		e.propagateFromNode(entry, initialState, nil, 0)
	}
	return e.flows
}

func (e *CrossContractTaintEngine) seedEntryPoint(
	node *CrossContractNode,
) *CrossContractTaintState {
	state := &CrossContractTaintState{
		TaintedParams:  make(map[int]taint.TaintLabel),
		TaintedStorage: make(map[string]taint.TaintLabel),
	}

	fn := e.findFunction(node)
	if fn == nil {
		return state
	}

	for i := range fn.Parameters {
		state.TaintedParams[i] = taint.TaintCalldata
	}

	// msg.sender and msg.value are always attacker-controlled inputs.
	state.TaintedParams[-1] = taint.TaintMsgSender
	state.TaintedParams[-2] = taint.TaintMsgValue

	return state
}

func (e *CrossContractTaintEngine) propagateFromNode(
	node *CrossContractNode,
	state *CrossContractTaintState,
	crossings []ContractBoundaryCrossing,
	depth int,
) {
	if depth > 10 {
		return
	}

	e.taintState[node.ID] = state

	fn := e.findFunction(node)
	if fn == nil {
		return
	}

	for _, edge := range node.Callees {
		e.processCalleeEdge(node, edge, fn, state, crossings, depth)
	}

	for _, unresolved := range e.graph.UnresolvedCalls {
		if unresolved.Caller != node.ID {
			continue
		}
		if e.hasTaintedArgs(state) {
			e.recordFlow(state, node.ID, crossings, unresolved.CallKind.toSinkKind())
		}
	}
}

func (e *CrossContractTaintEngine) processCalleeEdge(
	caller *CrossContractNode,
	edge *CrossContractEdge,
	callerFn *parser.UnifiedFunction,
	callerState *CrossContractTaintState,
	crossings []ContractBoundaryCrossing,
	depth int,
) {
	calleeNode, ok := e.graph.Nodes[edge.Callee]
	if !ok {
		return
	}

	calleeTaintedParams := e.propagateArguments(callerState, edge)

	if len(calleeTaintedParams) == 0 {
		return
	}

	calleeState := &CrossContractTaintState{
		TaintedParams:  calleeTaintedParams,
		TaintedStorage: make(map[string]taint.TaintLabel),
	}

	newCrossings := crossings
	if edge.CallKind.IsExternal() &&
		caller.ContractName != calleeNode.ContractName {
		crossing := ContractBoundaryCrossing{
			FromContract: caller.ContractName,
			ToContract:   calleeNode.ContractName,
			ViaFunction:  callerFn.Name,
			CallKind:     edge.CallKind,
			Line:         edge.CallLine,
		}
		newCrossings = append(newCrossings, crossing)
	}

	if edge.CallKind == CrossCallLowLevel || edge.CallKind == CrossCallDelegatecall {
		sinkKind := taint.SinkExternalCall
		if edge.CallKind == CrossCallDelegatecall {
			sinkKind = taint.SinkDelegatecall
		}
		e.recordFlow(callerState, caller.ID, newCrossings, sinkKind)
		return
	}

	// Continue propagating taint in the callee.
	e.propagateFromNode(calleeNode, calleeState, newCrossings, depth+1)
}

func (e *CrossContractTaintEngine) propagateArguments(
	callerState *CrossContractTaintState,
	edge *CrossContractEdge,
) map[int]taint.TaintLabel {
	result := make(map[int]taint.TaintLabel)

	if len(callerState.TaintedParams) == 0 {
		return result
	}

	callerLabel := e.highestTaintLabel(callerState)
	if callerLabel == taint.TaintNone {
		return result
	}

	callee, ok := e.graph.Nodes[edge.Callee]
	if !ok {
		return result
	}
	calleeFn := e.findFunction(callee)
	if calleeFn == nil {
		return result
	}

	for i := range calleeFn.Parameters {
		result[i] = taint.TaintDerived
	}
	// msg.sender and msg.value remain tainted in the callee context.
	result[-1] = taint.TaintMsgSender
	result[-2] = taint.TaintMsgValue

	return result
}

func (e *CrossContractTaintEngine) highestTaintLabel(
	state *CrossContractTaintState,
) taint.TaintLabel {
	priority := map[taint.TaintLabel]int{
		taint.TaintMsgSender:      6,
		taint.TaintMsgValue:       5,
		taint.TaintTxOrigin:       4,
		taint.TaintCalldata:       3,
		taint.TaintMsgData:        2,
		taint.TaintBlockTimestamp: 1,
		taint.TaintDerived:        0,
	}

	best := taint.TaintNone
	bestPriority := -1
	for _, label := range state.TaintedParams {
		if p := priority[label]; p > bestPriority {
			bestPriority = p
			best = label
		}
	}
	return best
}

func (e *CrossContractTaintEngine) hasTaintedArgs(
	state *CrossContractTaintState,
) bool {
	return len(state.TaintedParams) > 0
}

func (e *CrossContractTaintEngine) recordFlow(
	state *CrossContractTaintState,
	sinkFn GlobalFunctionID,
	crossings []ContractBoundaryCrossing,
	sinkKind taint.SinkKind,
) {
	if len(crossings) == 0 {
		return
	}

	label := e.highestTaintLabel(state)
	if label == taint.TaintNone {
		return
	}

	severity := analyzer.High
	if sinkKind == taint.SinkDelegatecall || sinkKind == taint.SinkSelfdestruct {
		severity = analyzer.Critical
	}

	crossingsCopy := make([]ContractBoundaryCrossing, len(crossings))
	copy(crossingsCopy, crossings)

	e.flows = append(e.flows, CrossContractTaintFlow{
		SourceFunction: NewGlobalFunctionID(crossings[0].FromContract, crossings[0].ViaFunction),
		SourceLabel:    label,
		Crossings:      crossingsCopy,
		SinkFunction:   sinkFn,
		SinkKind:       sinkKind,
		Severity:       severity,
	})
}

func (e *CrossContractTaintEngine) findFunction(
	node *CrossContractNode,
) *parser.UnifiedFunction {
	file, ok := e.project.ContractFile(node.ContractName)
	if !ok {
		return nil
	}
	for _, contract := range file.Contracts() {
		if contract.Name != node.ContractName {
			continue
		}
		for _, fn := range contract.Functions {
			if fn.Name == node.FunctionName {
				return fn
			}
		}
	}
	return nil
}

func (k CrossCallKind) toSinkKind() taint.SinkKind {
	switch k {
	case CrossCallDelegatecall:
		return taint.SinkDelegatecall
	default:
		return taint.SinkExternalCall
	}
}
