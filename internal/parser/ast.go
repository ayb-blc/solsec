package parser

import "encoding/json"

type Node struct {
	NodeType string `json:"nodeType"`

	Src string `json:"src"`

	ID int `json:"id,omitempty"`
}

type SourceUnit struct {
	Node
	AbsolutePath string     `json:"absolutePath"`
	Nodes        []*ASTNode `json:"nodes"`
}

// ASTNode models Solidity's tagged-union AST shape.
type ASTNode struct {
	NodeType string `json:"nodeType"`
	Src      string `json:"src"`
	ID       int    `json:"id,omitempty"`

	ContractDef     *ContractDefinition
	FunctionDef     *FunctionDefinition
	StateVarDecl    *StateVariableDeclaration
	VariableDecl    *VariableDeclaration
	ExpressionStmt  *ExpressionStatement
	VarDeclStmt     *VariableDeclarationStatement
	ReturnStmt      *Return
	IfStmt          *IfStatement
	ForStmt         *ForStatement
	EmitStmt        *EmitStatement
	Assignment      *Assignment
	FunctionCall    *FunctionCall
	MemberAccess    *MemberAccess
	BinaryOp        *BinaryOperation
	Identifier      *Identifier
	Literal         *Literal
	IndexAccess     *IndexAccess
	TupleExpression *TupleExpression
	Block           *Block
	ModifierDef     *ModifierDefinition
	ModifierInvoc   *ModifierInvocation

	Raw json.RawMessage
}

// UnmarshalJSON implements the standard JSON tagged-union decoding pattern.
func (n *ASTNode) UnmarshalJSON(data []byte) error {
	var base struct {
		NodeType string `json:"nodeType"`
		Src      string `json:"src"`
		ID       int    `json:"id,omitempty"`
	}
	if err := json.Unmarshal(data, &base); err != nil {
		return err
	}

	n.NodeType = base.NodeType
	n.Src = base.Src
	n.ID = base.ID
	n.Raw = data

	switch base.NodeType {
	case "ContractDefinition":
		n.ContractDef = &ContractDefinition{}
		return json.Unmarshal(data, n.ContractDef)
	case "FunctionDefinition":
		n.FunctionDef = &FunctionDefinition{}
		return json.Unmarshal(data, n.FunctionDef)
	case "StateVariableDeclaration":
		n.StateVarDecl = &StateVariableDeclaration{}
		return json.Unmarshal(data, n.StateVarDecl)
	case "VariableDeclaration":
		n.VariableDecl = &VariableDeclaration{}
		return json.Unmarshal(data, n.VariableDecl)
	case "ExpressionStatement":
		n.ExpressionStmt = &ExpressionStatement{}
		return json.Unmarshal(data, n.ExpressionStmt)
	case "VariableDeclarationStatement":
		n.VarDeclStmt = &VariableDeclarationStatement{}
		return json.Unmarshal(data, n.VarDeclStmt)
	case "Return":
		n.ReturnStmt = &Return{}
		return json.Unmarshal(data, n.ReturnStmt)
	case "IfStatement":
		n.IfStmt = &IfStatement{}
		return json.Unmarshal(data, n.IfStmt)
	case "ForStatement":
		n.ForStmt = &ForStatement{}
		return json.Unmarshal(data, n.ForStmt)
	case "EmitStatement":
		n.EmitStmt = &EmitStatement{}
		return json.Unmarshal(data, n.EmitStmt)
	case "Assignment":
		n.Assignment = &Assignment{}
		return json.Unmarshal(data, n.Assignment)
	case "FunctionCall":
		n.FunctionCall = &FunctionCall{}
		return json.Unmarshal(data, n.FunctionCall)
	case "MemberAccess":
		n.MemberAccess = &MemberAccess{}
		return json.Unmarshal(data, n.MemberAccess)
	case "BinaryOperation":
		n.BinaryOp = &BinaryOperation{}
		return json.Unmarshal(data, n.BinaryOp)
	case "Identifier":
		n.Identifier = &Identifier{}
		return json.Unmarshal(data, n.Identifier)
	case "Literal":
		n.Literal = &Literal{}
		return json.Unmarshal(data, n.Literal)
	case "IndexAccess":
		n.IndexAccess = &IndexAccess{}
		return json.Unmarshal(data, n.IndexAccess)
	case "TupleExpression":
		n.TupleExpression = &TupleExpression{}
		return json.Unmarshal(data, n.TupleExpression)
	case "Block":
		n.Block = &Block{}
		return json.Unmarshal(data, n.Block)
	case "ModifierDefinition":
		n.ModifierDef = &ModifierDefinition{}
		return json.Unmarshal(data, n.ModifierDef)
	case "ModifierInvocation":
		n.ModifierInvoc = &ModifierInvocation{}
		return json.Unmarshal(data, n.ModifierInvoc)
	}
	return nil
}

type ContractDefinition struct {
	Node
	Name          string `json:"name"`
	BaseContracts []struct {
		BaseName struct {
			Name string `json:"name"`
		} `json:"baseName"`
	} `json:"baseContracts"`
	Nodes []*ASTNode `json:"nodes"`
	// ContractKind: "contract", "interface", "library", "abstract"
	ContractKind string `json:"contractKind"`
}

func (c *ContractDefinition) InheritsFrom(name string) bool {
	for _, base := range c.BaseContracts {
		if base.BaseName.Name == name {
			return true
		}
	}
	return false
}

type FunctionDefinition struct {
	Node
	Name            string         `json:"name"`
	Visibility      string         `json:"visibility"`      // public, external, internal, private
	StateMutability string         `json:"stateMutability"` // pure, view, payable, nonpayable
	Modifiers       []*ASTNode     `json:"modifiers"`
	Parameters      *ParameterList `json:"parameters"`
	Body            *ASTNode       `json:"body"`
	IsConstructor   bool           `json:"isConstructor"`
	Kind            string         `json:"kind"` // "constructor", "fallback", "receive", "function"
}

func (f *FunctionDefinition) HasModifier(name string) bool {
	for _, mod := range f.Modifiers {
		if mod.ModifierInvoc != nil && mod.ModifierInvoc.ModifierName.Name == name {
			return true
		}
	}
	return false
}

type ParameterList struct {
	Node
	Parameters []*VariableDeclaration `json:"parameters"`
}

type StateVariableDeclaration struct {
	Node
	Variables    []*VariableDeclaration `json:"variables"`
	InitialValue *ASTNode               `json:"initialValue,omitempty"`
}

type VariableDeclaration struct {
	Node
	Name            string   `json:"name"`
	TypeName        *ASTNode `json:"typeName"`
	Visibility      string   `json:"visibility"`
	StateVariable   bool     `json:"stateVariable"`
	StorageLocation string   `json:"storageLocation"` // storage, memory, calldata
	Mutability      string   `json:"mutability"`      // mutable, immutable, constant
}

type Block struct {
	Node
	Statements []*ASTNode `json:"statements"`
}

type ExpressionStatement struct {
	Node
	Expression *ASTNode `json:"expression"`
}

type VariableDeclarationStatement struct {
	Node
	Declarations []*ASTNode `json:"declarations"`
	InitialValue *ASTNode   `json:"initialValue"`
}

type Return struct {
	Node
	Expression *ASTNode `json:"expression,omitempty"`
}

type IfStatement struct {
	Node
	Condition *ASTNode `json:"condition"`
	TrueBody  *ASTNode `json:"trueBody"`
	FalseBody *ASTNode `json:"falseBody,omitempty"`
}

type ForStatement struct {
	Node
	InitializationExpression *ASTNode `json:"initializationExpression,omitempty"`
	Condition                *ASTNode `json:"condition,omitempty"`
	LoopExpression           *ASTNode `json:"loopExpression,omitempty"`
	Body                     *ASTNode `json:"body"`
}

type EmitStatement struct {
	Node
	EventCall *ASTNode `json:"eventCall"`
}

type Assignment struct {
	Node
	Operator      string   `json:"operator"` // =, +=, -=, *=, /=
	LeftHandSide  *ASTNode `json:"leftHandSide"`
	RightHandSide *ASTNode `json:"rightHandSide"`
}

type FunctionCall struct {
	Node
	Expression *ASTNode   `json:"expression"`
	Arguments  []*ASTNode `json:"arguments"`
	Names      []string   `json:"names,omitempty"`
}

type MemberAccess struct {
	Node
	Expression *ASTNode `json:"expression"`
	MemberName string   `json:"memberName"`
}

type BinaryOperation struct {
	Node
	Operator        string   `json:"operator"` // ==, !=, >=, <=, +, -, *, /
	LeftExpression  *ASTNode `json:"leftExpression"`
	RightExpression *ASTNode `json:"rightExpression"`
}

type Identifier struct {
	Node
	Name                  string `json:"name"`
	ReferencedDeclaration int    `json:"referencedDeclaration,omitempty"`
}

type Literal struct {
	Node
	Kind  string `json:"kind"` // number, string, bool, hexString
	Value string `json:"value"`
}

type IndexAccess struct {
	Node
	BaseExpression  *ASTNode `json:"baseExpression"`
	IndexExpression *ASTNode `json:"indexExpression,omitempty"`
}

type TupleExpression struct {
	Node
	Components    []*ASTNode `json:"components"`
	IsInlineArray bool       `json:"isInlineArray"`
}

type ModifierDefinition struct {
	Node
	Name string   `json:"name"`
	Body *ASTNode `json:"body"`
}

type ModifierInvocation struct {
	Node
	ModifierName struct {
		Name string `json:"name"`
	} `json:"modifierName"`
	Arguments []*ASTNode `json:"arguments,omitempty"`
}
