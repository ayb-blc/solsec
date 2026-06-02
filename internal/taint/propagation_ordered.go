package taint

import (
	"github.com/ayb-blc/solsec/internal/symboltable"
)

type OrderedPropagator struct {
	relation *TaintRelation
	engine   *Engine
}

func NewOrderedPropagator(engine *Engine, indexDB *symboltable.IndexDB) *OrderedPropagator {
	return &OrderedPropagator{
		relation: NewTaintRelation(indexDB, engine.table),
		engine:   engine,
	}
}

func (op *OrderedPropagator) Propagate() {
	for len(op.engine.worklist) > 0 {
		src := op.engine.worklist[0]
		op.engine.worklist = op.engine.worklist[1:]

		tainted := op.relation.IsTaintedByTransitive(src)

		for _, candidate := range tainted {
			if op.engine.isTainted(candidate) {
				continue
			}

			srcTaint := op.engine.taintMap[src.SolcID]
			var chain []*symboltable.Symbol
			if srcTaint != nil {
				chain = make([]*symboltable.Symbol, len(srcTaint.PropagationChain))
				copy(chain, srcTaint.PropagationChain)
				chain = append(chain, src)
			}

			derivedSource := TaintSource{
				Label:       TaintDerived,
				Description: "Derived from '" + src.Name + "' via ordered propagation",
			}

			op.engine.taintSymbolWithChain(candidate, derivedSource, chain)
		}
	}
}

func (op *OrderedPropagator) PropagateOne(
	src *symboltable.Symbol,
) []*symboltable.Symbol {
	var newlyTainted []*symboltable.Symbol

	for _, candidate := range op.engine.table.AllSymbols {
		if op.engine.isTainted(candidate) {
			continue
		}
		if op.relation.IsTaintedBy(candidate, src) {
			newlyTainted = append(newlyTainted, candidate)
		}
	}

	return newlyTainted
}
