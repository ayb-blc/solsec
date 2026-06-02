package taint

import (
	"github.com/ayb-blc/solsec/internal/callgraph"
	"github.com/ayb-blc/solsec/internal/symboltable"
)

// StorageTaintRead represents a persistent tainted state value being read from
// a function. Persistent storage matters because user-controlled input can be
// written in one transaction and consumed later in another transaction.
type StorageTaintRead struct {
	Symbol       *symboltable.Symbol
	FunctionID   callgraph.FunctionID
	FunctionName string
	ContractName string
	Read         symboltable.Usage
	Label        TaintLabel
	Reachable    bool
}

// StorageTaintTracker tracks taint that survives across function boundaries by
// living in contract storage.
type StorageTaintTracker struct {
	table *symboltable.SymbolTable
	cg    *callgraph.CallGraph

	tainted map[string]TaintLabel
}

func NewStorageTaintTracker(
	table *symboltable.SymbolTable,
	cg *callgraph.CallGraph,
) *StorageTaintTracker {
	return &StorageTaintTracker{
		table:   table,
		cg:      cg,
		tainted: make(map[string]TaintLabel),
	}
}

// SeedFromSymbolTable marks state variables as tainted when symbol analysis
// already identified them as user-controlled, or when they are written from an
// externally reachable function. The latter is conservative: without complete
// expression-level dataflow, a public setter is a realistic attacker-controlled
// storage source.
func (t *StorageTaintTracker) SeedFromSymbolTable() {
	if t == nil || t.table == nil {
		return
	}

	for _, sym := range t.table.AllSymbols {
		if sym == nil || !sym.IsStateVariable() || !sym.IsWritable() {
			continue
		}

		if sym.IsUserControlled {
			t.tainted[sym.Name] = TaintCalldata
			continue
		}

		for _, write := range sym.Writes {
			if t.isExternallyReachable(write.InFunction) {
				t.tainted[sym.Name] = TaintCalldata
				break
			}
		}
	}
}

// PropagateToReads reports reads of tainted storage. This is useful for later
// detectors that need to connect "stored attacker input" to dangerous sinks.
func (t *StorageTaintTracker) PropagateToReads() []StorageTaintRead {
	if t == nil || t.table == nil {
		return nil
	}

	var reads []StorageTaintRead
	for _, sym := range t.table.AllSymbols {
		if sym == nil || !sym.IsStateVariable() {
			continue
		}

		label, ok := t.tainted[sym.Name]
		if !ok {
			continue
		}

		for _, read := range sym.Reads {
			fnID, reachable := t.resolveFunction(read.InFunction)
			reads = append(reads, StorageTaintRead{
				Symbol:       sym,
				FunctionID:   fnID,
				FunctionName: read.InFunction,
				ContractName: fnID.Contract(),
				Read:         read,
				Label:        label,
				Reachable:    reachable,
			})
		}
	}

	return reads
}

func (t *StorageTaintTracker) isExternallyReachable(functionName string) bool {
	if _, reachable := t.resolveFunction(functionName); reachable {
		return true
	}
	return false
}

func (t *StorageTaintTracker) resolveFunction(functionName string) (callgraph.FunctionID, bool) {
	if t == nil || t.cg == nil || functionName == "" {
		return "", false
	}

	for id, node := range t.cg.Nodes {
		if node == nil || node.Name != functionName {
			continue
		}
		if node.Visibility == "public" || node.Visibility == "external" || node.IsReachableFromExternal {
			return id, true
		}
	}

	return "", false
}
