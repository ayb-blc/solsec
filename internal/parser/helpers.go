package parser

import (
	"encoding/json"
	"fmt"
	"strings"
)

// VariableName extracts the declared identifier from a VariableDeclaration node.
//
// Solidity's AST wraps local declarations in VariableDeclarationStatement, whose
// declarations are regular ASTNode values. Keeping this helper in parser avoids
// duplicating AST-shape knowledge in analysis packages.
func VariableName(node *ASTNode) string {
	if node == nil {
		return ""
	}
	if node.VariableDecl != nil {
		return node.VariableDecl.Name
	}
	if node.Identifier != nil {
		return node.Identifier.Name
	}

	// Fallback for ASTs parsed before this node type was modeled.
	var raw struct {
		Name string `json:"name"`
	}
	if len(node.Raw) > 0 && json.Unmarshal(node.Raw, &raw) == nil {
		return raw.Name
	}
	return ""
}

// BaseIdentifierName returns the root identifier written or read by an expression.
//
// Examples:
//
//	balances[msg.sender] -> balances
//	user.balance         -> user
//	amount               -> amount
//
// Security detectors use the base identifier because writes through mappings,
// arrays, and structs still mutate the root state variable.
func BaseIdentifierName(node *ASTNode) string {
	if node == nil {
		return ""
	}

	switch node.NodeType {
	case "Identifier":
		if node.Identifier != nil {
			return node.Identifier.Name
		}
	case "IndexAccess":
		if node.IndexAccess != nil {
			return BaseIdentifierName(node.IndexAccess.BaseExpression)
		}
	case "MemberAccess":
		if node.MemberAccess != nil {
			return BaseIdentifierName(node.MemberAccess.Expression)
		}
	}

	return ""
}

// TypeNameString extracts a Solidity type string from a typeName AST node.
//
// Prefer solc's typeDescriptions.typeString when available because it already
// normalizes aliases such as uint -> uint256. When that field is absent, fall
// back to the explicit typeName node shape.
func TypeNameString(node *ASTNode) string {
	if node == nil {
		return "unknown"
	}

	if typeString := rawTypeString(node); typeString != "" {
		return typeString
	}

	switch node.NodeType {
	case "ElementaryTypeName":
		var raw struct {
			Name string `json:"name"`
		}
		if unmarshalRaw(node, &raw) && raw.Name != "" {
			return raw.Name
		}

	case "UserDefinedTypeName":
		var raw struct {
			Name     string `json:"name"`
			PathNode struct {
				Name string `json:"name"`
			} `json:"pathNode"`
			ReferencedDeclaration int `json:"referencedDeclaration"`
		}
		if unmarshalRaw(node, &raw) {
			if raw.PathNode.Name != "" {
				return raw.PathNode.Name
			}
			if raw.Name != "" {
				return raw.Name
			}
			if raw.ReferencedDeclaration != 0 {
				return fmt.Sprintf("user_defined#%d", raw.ReferencedDeclaration)
			}
		}

	case "Mapping":
		var raw struct {
			KeyType   *ASTNode `json:"keyType"`
			ValueType *ASTNode `json:"valueType"`
		}
		if unmarshalRaw(node, &raw) {
			return fmt.Sprintf(
				"mapping(%s => %s)",
				TypeNameString(raw.KeyType),
				TypeNameString(raw.ValueType),
			)
		}

	case "ArrayTypeName":
		var raw struct {
			BaseType *ASTNode `json:"baseType"`
			Length   *ASTNode `json:"length"`
		}
		if unmarshalRaw(node, &raw) {
			if raw.Length != nil && raw.Length.Literal != nil && raw.Length.Literal.Value != "" {
				return fmt.Sprintf("%s[%s]", TypeNameString(raw.BaseType), raw.Length.Literal.Value)
			}
			return TypeNameString(raw.BaseType) + "[]"
		}

	case "FunctionTypeName":
		return "function"
	}

	if node.NodeType != "" {
		return node.NodeType
	}
	return "unknown"
}

func rawTypeString(node *ASTNode) string {
	var raw struct {
		TypeDescriptions struct {
			TypeString string `json:"typeString"`
		} `json:"typeDescriptions"`
	}
	if unmarshalRaw(node, &raw) {
		return strings.TrimSpace(raw.TypeDescriptions.TypeString)
	}
	return ""
}

func unmarshalRaw(node *ASTNode, target any) bool {
	return node != nil && len(node.Raw) > 0 && json.Unmarshal(node.Raw, target) == nil
}
