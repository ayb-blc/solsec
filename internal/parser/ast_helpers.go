package parser

func ExtractVarName(node *ASTNode) string {
	return VariableName(node)
}

func ExtractBaseName(node *ASTNode) string {
	return BaseIdentifierName(node)
}

func ExtractFullName(node *ASTNode) string {
	if node == nil {
		return ""
	}
	switch node.NodeType {
	case "Identifier":
		if node.Identifier != nil {
			return node.Identifier.Name
		}
	case "MemberAccess":
		if node.MemberAccess != nil {
			base := ExtractFullName(node.MemberAccess.Expression)
			if base != "" {
				return base + "." + node.MemberAccess.MemberName
			}
			return node.MemberAccess.MemberName
		}
	case "IndexAccess":
		if node.IndexAccess != nil {
			base := ExtractFullName(node.IndexAccess.BaseExpression)
			idx := ExtractFullName(node.IndexAccess.IndexExpression)
			if idx != "" {
				return base + "[" + idx + "]"
			}
			return base + "[...]"
		}
	}
	return ""
}
