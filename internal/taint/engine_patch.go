package taint

import (
	"github.com/ayb-blc/solsec/internal/parser"
	"github.com/ayb-blc/solsec/internal/symboltable"
)

//
//   indexDB   *symboltable.IndexDB
//   propagator *OrderedPropagator

func NewEngineOrdered(
	table *symboltable.SymbolTable,
	unit *parser.SourceUnit,
	indexDB *symboltable.IndexDB,
) *Engine {
	e := &Engine{
		table:    table,
		unit:     unit,
		taintMap: make(map[int]*TaintedValue),
		indexDB:  indexDB,
	}
	e.propagator = NewOrderedPropagator(e, indexDB)
	return e
}

// AnalyzeOrdered ordered propagation ile tam analiz.
func (e *Engine) AnalyzeOrdered() []TaintFlow {
	e.seedSources()

	if e.propagator != nil {
		e.propagator.Propagate()
	} else {
		// Fallback: eski propagation
		e.propagate()
	}

	e.checkSinks()

	return e.flows
}
