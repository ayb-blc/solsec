package taint

import (
	"github.com/ayb-blc/solsec/internal/symboltable"
)

type TaintRelation struct {
	indexDB *symboltable.IndexDB
	table   *symboltable.SymbolTable
}

func NewTaintRelation(
	indexDB *symboltable.IndexDB,
	table *symboltable.SymbolTable,
) *TaintRelation {
	return &TaintRelation{indexDB: indexDB, table: table}
}

func (tr *TaintRelation) IsTaintedBy(
	candidate, src *symboltable.Symbol,
) bool {
	if tr == nil || candidate == nil || src == nil {
		return false
	}
	if candidate.SolcID == src.SolcID {
		return false
	}

	for _, write := range candidate.Writes {
		for _, read := range src.Reads {
			if tr.writeReceivesTaintFromRead(write, read, src) {
				return true
			}
		}
	}
	return false
}

func (tr *TaintRelation) writeReceivesTaintFromRead(
	write, read symboltable.Usage,
	src *symboltable.Symbol,
) bool {
	if write.InFunction != read.InFunction {
		return false
	}

	if !tr.writeComesAfterRead(write, read) {
		return false
	}

	return tr.rhsContainsSrc(write, src)
}

func (tr *TaintRelation) writeComesAfterRead(
	write, read symboltable.Usage,
) bool {
	if tr.indexDB == nil {
		return write.ScopeID == read.ScopeID ||
			write.InFunction == read.InFunction
	}
	writeIdx, writeOK := tr.indexDB.IndexOfUsage(write)
	readIdx, readOK := tr.indexDB.IndexOfUsage(read)

	if writeOK && readOK {
		if !writeIdx.SameFunctionScope(readIdx) {
			return false
		}
		return writeIdx.SameOrAfter(readIdx)
	}

	if writeOK && !readOK {
		return writeIdx.FunctionScopeID == read.ScopeID
	}

	if !writeOK && readOK {
		return write.ScopeID == readIdx.FunctionScopeID
	}

	return write.ScopeID == read.ScopeID ||
		write.InFunction == read.InFunction
}

func (tr *TaintRelation) rhsContainsSrc(
	write symboltable.Usage,
	src *symboltable.Symbol,
) bool {
	if tr.indexDB == nil {
		for _, read := range src.Reads {
			if read.InFunction == write.InFunction {
				return true
			}
		}
		return false
	}
	writeIdx, writeOK := tr.indexDB.IndexOfUsage(write)
	if !writeOK {
		for _, read := range src.Reads {
			if read.InFunction == write.InFunction {
				return true
			}
		}
		return false
	}

	for _, read := range src.Reads {
		readIdx, readOK := tr.indexDB.IndexOfUsage(read)
		if !readOK {
			continue
		}
		if writeIdx.FunctionScopeID == readIdx.FunctionScopeID &&
			writeIdx.TopLevel == readIdx.TopLevel {
			return true
		}
		if writeIdx.FunctionScopeID == readIdx.FunctionScopeID &&
			writeIdx.SameOrAfter(readIdx) {
			return true
		}
	}

	return false
}

func (tr *TaintRelation) IsTaintedByTransitive(
	src *symboltable.Symbol,
) []*symboltable.Symbol {
	visited := make(map[int]bool)
	queue := []*symboltable.Symbol{src}
	var result []*symboltable.Symbol
	if tr == nil || tr.table == nil || src == nil {
		return result
	}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		if visited[current.SolcID] {
			continue
		}
		visited[current.SolcID] = true

		for _, candidate := range tr.table.AllSymbols {
			if visited[candidate.SolcID] {
				continue
			}
			if tr.IsTaintedBy(candidate, current) {
				result = append(result, candidate)
				queue = append(queue, candidate)
			}
		}
	}

	return result
}
