package symboltable

import "github.com/ayb-blc/solsec/internal/parser"

// Top-level statement index + nested derinlik bilgisi birlikte tutulur.
type StatementIndex struct {
	TopLevel int

	NestedPath []int

	FunctionScopeID ScopeID

	NodeID int
}

func (si StatementIndex) Before(other StatementIndex) bool {
	if si.FunctionScopeID != other.FunctionScopeID {
		return false
	}
	if si.TopLevel != other.TopLevel {
		return si.TopLevel < other.TopLevel
	}
	minLen := len(si.NestedPath)
	if len(other.NestedPath) < minLen {
		minLen = len(other.NestedPath)
	}
	for i := 0; i < minLen; i++ {
		if si.NestedPath[i] != other.NestedPath[i] {
			return si.NestedPath[i] < other.NestedPath[i]
		}
	}
	return len(si.NestedPath) < len(other.NestedPath)
}

func (si StatementIndex) After(other StatementIndex) bool {
	return other.Before(si)
}

func (si StatementIndex) SameOrAfter(other StatementIndex) bool {
	return !si.Before(other)
}

func (si StatementIndex) SameFunctionScope(other StatementIndex) bool {
	return si.FunctionScopeID == other.FunctionScopeID
}

type IndexDB struct {
	nodeIndex map[int]StatementIndex

	usageIndex map[int]StatementIndex
}

func NewIndexDB() *IndexDB {
	return &IndexDB{
		nodeIndex:  make(map[int]StatementIndex),
		usageIndex: make(map[int]StatementIndex),
	}
}

func (db *IndexDB) Register(
	block *parser.Block,
	fnScopeID ScopeID,
	topLevelOffset int,
	nestedPath []int,
) {
	if block == nil {
		return
	}

	for i, stmt := range block.Statements {
		if stmt == nil {
			continue
		}

		idx := StatementIndex{
			TopLevel:        topLevelOffset + i,
			NestedPath:      copyPath(nestedPath),
			FunctionScopeID: fnScopeID,
			NodeID:          stmt.ID,
		}

		db.nodeIndex[stmt.ID] = idx
		db.registerExpression(stmt, idx, fnScopeID)
		db.registerNested(stmt, fnScopeID, topLevelOffset+i, nestedPath)
	}
}

func (db *IndexDB) registerNested(
	node *parser.ASTNode,
	fnScopeID ScopeID,
	topLevel int,
	currentPath []int,
) {
	if node == nil {
		return
	}

	switch node.NodeType {

	case "IfStatement":
		if node.IfStmt == nil {
			return
		}
		// TrueBody
		if node.IfStmt.TrueBody != nil && node.IfStmt.TrueBody.Block != nil {
			truePath := appendPath(currentPath, 0)
			db.registerBlockInPath(node.IfStmt.TrueBody.Block, fnScopeID, topLevel, truePath)
		}
		// FalseBody
		if node.IfStmt.FalseBody != nil && node.IfStmt.FalseBody.Block != nil {
			falsePath := appendPath(currentPath, 1)
			db.registerBlockInPath(node.IfStmt.FalseBody.Block, fnScopeID, topLevel, falsePath)
		}

	case "ForStatement":
		if node.ForStmt != nil && node.ForStmt.Body != nil &&
			node.ForStmt.Body.Block != nil {
			forPath := appendPath(currentPath, 0)
			db.registerBlockInPath(node.ForStmt.Body.Block, fnScopeID, topLevel, forPath)
		}

	case "WhileStatement":
		// WhileStatement body'si
		if body := extractWhileBody(node); body != nil {
			whilePath := appendPath(currentPath, 0)
			db.registerBlockInPath(body, fnScopeID, topLevel, whilePath)
		}

	case "Block":
		if node.Block != nil {
			blockPath := appendPath(currentPath, 0)
			db.registerBlockInPath(node.Block, fnScopeID, topLevel, blockPath)
		}
	}
}

func (db *IndexDB) registerBlockInPath(
	block *parser.Block,
	fnScopeID ScopeID,
	topLevel int,
	path []int,
) {
	for i, stmt := range block.Statements {
		if stmt == nil {
			continue
		}
		childPath := appendPath(path, i)
		idx := StatementIndex{
			TopLevel:        topLevel,
			NestedPath:      childPath,
			FunctionScopeID: fnScopeID,
			NodeID:          stmt.ID,
		}
		db.nodeIndex[stmt.ID] = idx
		db.registerExpression(stmt, idx, fnScopeID)
		db.registerNested(stmt, fnScopeID, topLevel, childPath)
	}
}

func (db *IndexDB) registerExpression(
	node *parser.ASTNode,
	parentIdx StatementIndex,
	fnScopeID ScopeID,
) {
	if node == nil {
		return
	}

	// Record this node as well; it may be an expression.
	if node.ID != 0 {
		if _, exists := db.nodeIndex[node.ID]; !exists {
			db.nodeIndex[node.ID] = parentIdx
		}
	}

	switch node.NodeType {
	case "ExpressionStatement":
		if node.ExpressionStmt != nil {
			db.registerExpression(node.ExpressionStmt.Expression, parentIdx, fnScopeID)
		}
	case "VariableDeclarationStatement":
		if node.VarDeclStmt != nil {
			db.registerExpression(node.VarDeclStmt.InitialValue, parentIdx, fnScopeID)
			for _, decl := range node.VarDeclStmt.Declarations {
				db.registerExpression(decl, parentIdx, fnScopeID)
			}
		}
	case "Assignment":
		if node.Assignment != nil {
			db.registerExpression(node.Assignment.LeftHandSide, parentIdx, fnScopeID)
			db.registerExpression(node.Assignment.RightHandSide, parentIdx, fnScopeID)
		}
	case "FunctionCall":
		if node.FunctionCall != nil {
			db.registerExpression(node.FunctionCall.Expression, parentIdx, fnScopeID)
			for _, arg := range node.FunctionCall.Arguments {
				db.registerExpression(arg, parentIdx, fnScopeID)
			}
		}
	case "BinaryOperation":
		if node.BinaryOp != nil {
			db.registerExpression(node.BinaryOp.LeftExpression, parentIdx, fnScopeID)
			db.registerExpression(node.BinaryOp.RightExpression, parentIdx, fnScopeID)
		}
	case "MemberAccess":
		if node.MemberAccess != nil {
			db.registerExpression(node.MemberAccess.Expression, parentIdx, fnScopeID)
		}
	case "IndexAccess":
		if node.IndexAccess != nil {
			db.registerExpression(node.IndexAccess.BaseExpression, parentIdx, fnScopeID)
			db.registerExpression(node.IndexAccess.IndexExpression, parentIdx, fnScopeID)
		}
	case "Return":
		if node.ReturnStmt != nil {
			db.registerExpression(node.ReturnStmt.Expression, parentIdx, fnScopeID)
		}
	case "TupleExpression":
		if node.TupleExpression != nil {
			for _, comp := range node.TupleExpression.Components {
				db.registerExpression(comp, parentIdx, fnScopeID)
			}
		}
	}
}

func (db *IndexDB) IndexOf(node *parser.ASTNode) (StatementIndex, bool) {
	if node == nil || node.ID == 0 {
		return StatementIndex{}, false
	}
	idx, ok := db.nodeIndex[node.ID]
	return idx, ok
}

func (db *IndexDB) IndexOfUsage(u Usage) (StatementIndex, bool) {
	if u.Node == nil || u.Node.ID == 0 {
		return StatementIndex{
			FunctionScopeID: u.ScopeID,
			TopLevel:        -1,
		}, false
	}
	return db.IndexOf(u.Node)
}

func copyPath(p []int) []int {
	if len(p) == 0 {
		return nil
	}
	out := make([]int, len(p))
	copy(out, p)
	return out
}

func appendPath(p []int, i int) []int {
	out := make([]int, len(p)+1)
	copy(out, p)
	out[len(p)] = i
	return out
}

func extractWhileBody(node *parser.ASTNode) *parser.Block {
	if node.Raw == nil {
		return nil
	}
	return nil
}
