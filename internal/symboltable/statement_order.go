package symboltable

type StatementOrderDB struct {
	fnStatementOrder map[ScopeID]map[int]int
	scopeToFunction  map[ScopeID]ScopeID
}

func NewStatementOrderDB() *StatementOrderDB {
	return &StatementOrderDB{
		fnStatementOrder: make(map[ScopeID]map[int]int),
		scopeToFunction:  make(map[ScopeID]ScopeID),
	}
}

func (db *StatementOrderDB) Register(fnScopeID ScopeID, order map[int]int) {
	db.fnStatementOrder[fnScopeID] = order
	db.scopeToFunction[fnScopeID] = fnScopeID
}

func (db *StatementOrderDB) RegisterScope(scope *Scope) {
	if db == nil || scope == nil {
		return
	}
	fn := scope.FunctionScope()
	if fn != nil {
		db.scopeToFunction[scope.ID] = fn.ID
	}
}

func (db *StatementOrderDB) StatementIndex(fnScopeID ScopeID, nodeID int) int {
	if db == nil {
		return -1
	}
	if canonical, ok := db.scopeToFunction[fnScopeID]; ok {
		fnScopeID = canonical
	}
	order, ok := db.fnStatementOrder[fnScopeID]
	if !ok {
		return -1
	}
	idx, ok := order[nodeID]
	if !ok {
		return -1
	}
	return idx
}

func (db *StatementOrderDB) UsageIndex(usage Usage) int {
	if usage.Node == nil {
		return -1
	}
	return db.StatementIndex(usage.ScopeID, usage.Node.ID)
}

func (db *StatementOrderDB) SameFunctionScope(a, b ScopeID) bool {
	if db == nil {
		return a == b
	}
	aFn, aOK := db.scopeToFunction[a]
	bFn, bOK := db.scopeToFunction[b]
	if aOK && bOK {
		return aFn == bFn
	}
	return a == b
}
