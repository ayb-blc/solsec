package taint

import (
	"github.com/ayb-blc/solsec/internal/parser"
	"github.com/ayb-blc/solsec/internal/symboltable"
)

//   orderDB *symboltable.StatementOrderDB

func NewEngineWithOrder(
	table *symboltable.SymbolTable,
	unit *parser.SourceUnit,
	orderDB *symboltable.StatementOrderDB,
) *Engine {
	return &Engine{
		table:    table,
		unit:     unit,
		taintMap: make(map[int]*TaintedValue),
		orderDB:  orderDB,
	}
}
