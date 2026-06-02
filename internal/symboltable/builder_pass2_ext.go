// Pass 2'de statement order DB'yi dolduran ek kod

package symboltable

import "github.com/ayb-blc/solsec/internal/parser"

func (b *Builder) registerStatementOrder(
	fd *parser.FunctionDefinition,
	fnScope *Scope,
	orderDB *StatementOrderDB,
) {
	if fd.Body == nil || fd.Body.Block == nil {
		return
	}
	order := buildStatementOrder(fd.Body.Block)
	orderDB.Register(fnScope.ID, order)
}

//
// func Build(unit *SourceUnit, srcMap *SourceMap) (*SymbolTable, *StatementOrderDB, error) {
//     ...
//     orderDB := NewStatementOrderDB()
//     return st, orderDB, nil
// }
