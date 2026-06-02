package taint

import (
	"github.com/ayb-blc/solsec/internal/symboltable"
)

func isTaintedByOrdered(
	candidate, src *symboltable.Symbol,
	orderDB *symboltable.StatementOrderDB,
) bool {
	if candidate.SolcID == src.SolcID {
		return false
	}

	for _, write := range candidate.Writes {
		writeFnScope := write.ScopeID

		for _, read := range src.Reads {
			readFnScope := read.ScopeID
			if !sameFunctionScope(writeFnScope, readFnScope, orderDB) {
				continue
			}

			writeIdx := orderDB.UsageIndex(write)
			readIdx := orderDB.UsageIndex(read)

			if writeIdx < 0 || readIdx < 0 {
				if write.InFunction == read.InFunction {
					return true
				}
				continue
			}

			if writeIdx >= readIdx {
				return true
			}
		}
	}

	return false
}

func sameFunctionScope(
	a, b symboltable.ScopeID,
	orderDB *symboltable.StatementOrderDB,
) bool {
	return orderDB.SameFunctionScope(a, b)
}

func (e *Engine) isTaintedByFull(
	candidate, src *symboltable.Symbol,
) bool {
	if candidate.SolcID == src.SolcID {
		return false
	}

	if e.orderDB == nil {
		for _, write := range candidate.Writes {
			for _, read := range src.Reads {
				if write.InFunction == read.InFunction &&
					write.ScopeID == read.ScopeID {
					return true
				}
			}
		}
		return false
	}

	return isTaintedByOrdered(candidate, src, e.orderDB)
}
