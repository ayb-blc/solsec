package symboltable

func (db *IndexDB) ForceRegister(nodeID int, idx StatementIndex) {
	db.nodeIndex[nodeID] = idx
}
