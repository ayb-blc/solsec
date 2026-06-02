package parser

// Visitor supports early termination with selective descent.
type Visitor interface {
	Visit(node *ASTNode) bool
}

type VisitorFunc func(node *ASTNode) bool

func (f VisitorFunc) Visit(node *ASTNode) bool {
	return f(node)
}

// Walk traverses the AST in depth-first pre-order.
func Walk(node *ASTNode, visitor Visitor) {
	if node == nil {
		return
	}

	// Visit this node.
	if !visitor.Visit(node) {
		return
	}

	walkChildren(node, visitor)
}

func WalkSourceUnit(unit *SourceUnit, visitor Visitor) {
	for _, node := range unit.Nodes {
		Walk(node, visitor)
	}
}

func walkChildren(node *ASTNode, visitor Visitor) {
	switch node.NodeType {
	case "ContractDefinition":
		if node.ContractDef != nil {
			for _, child := range node.ContractDef.Nodes {
				Walk(child, visitor)
			}
		}

	case "FunctionDefinition":
		if node.FunctionDef != nil {
			for _, mod := range node.FunctionDef.Modifiers {
				Walk(mod, visitor)
			}
			// Function body'yi ziyaret et
			Walk(node.FunctionDef.Body, visitor)
		}

	case "ModifierDefinition":
		if node.ModifierDef != nil {
			Walk(node.ModifierDef.Body, visitor)
		}

	case "Block":
		if node.Block != nil {
			for _, stmt := range node.Block.Statements {
				Walk(stmt, visitor)
			}
		}

	case "ExpressionStatement":
		if node.ExpressionStmt != nil {
			Walk(node.ExpressionStmt.Expression, visitor)
		}

	case "VariableDeclarationStatement":
		if node.VarDeclStmt != nil {
			for _, decl := range node.VarDeclStmt.Declarations {
				Walk(decl, visitor)
			}
			Walk(node.VarDeclStmt.InitialValue, visitor)
		}

	case "IfStatement":
		if node.IfStmt != nil {
			Walk(node.IfStmt.Condition, visitor)
			Walk(node.IfStmt.TrueBody, visitor)
			Walk(node.IfStmt.FalseBody, visitor)
		}

	case "ForStatement":
		if node.ForStmt != nil {
			Walk(node.ForStmt.InitializationExpression, visitor)
			Walk(node.ForStmt.Condition, visitor)
			Walk(node.ForStmt.Body, visitor)
			Walk(node.ForStmt.LoopExpression, visitor)
		}

	case "Return":
		if node.ReturnStmt != nil {
			Walk(node.ReturnStmt.Expression, visitor)
		}

	case "EmitStatement":
		if node.EmitStmt != nil {
			Walk(node.EmitStmt.EventCall, visitor)
		}

	case "Assignment":
		if node.Assignment != nil {
			Walk(node.Assignment.LeftHandSide, visitor)
			Walk(node.Assignment.RightHandSide, visitor)
		}

	case "FunctionCall":
		if node.FunctionCall != nil {
			Walk(node.FunctionCall.Expression, visitor)
			for _, arg := range node.FunctionCall.Arguments {
				Walk(arg, visitor)
			}
		}

	case "MemberAccess":
		if node.MemberAccess != nil {
			Walk(node.MemberAccess.Expression, visitor)
		}

	case "BinaryOperation":
		if node.BinaryOp != nil {
			Walk(node.BinaryOp.LeftExpression, visitor)
			Walk(node.BinaryOp.RightExpression, visitor)
		}

	case "IndexAccess":
		if node.IndexAccess != nil {
			Walk(node.IndexAccess.BaseExpression, visitor)
			Walk(node.IndexAccess.IndexExpression, visitor)
		}

	case "TupleExpression":
		if node.TupleExpression != nil {
			for _, comp := range node.TupleExpression.Components {
				Walk(comp, visitor)
			}
		}

	case "Identifier", "Literal", "ElementaryTypeName", "VariableDeclaration":
		return
	}
}
