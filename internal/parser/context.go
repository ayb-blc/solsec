package parser

type AnalysisContext struct {
	// contractStack aktif contract stack'i
	contractStack []*ContractDefinition

	functionStack []*FunctionDefinition

	// modifierStack aktif modifier stack'i
	modifierStack []*ModifierDefinition

	statementDepth int
}

func (ctx *AnalysisContext) CurrentContract() *ContractDefinition {
	if len(ctx.contractStack) == 0 {
		return nil
	}
	return ctx.contractStack[len(ctx.contractStack)-1]
}

func (ctx *AnalysisContext) CurrentFunction() *FunctionDefinition {
	if len(ctx.functionStack) == 0 {
		return nil
	}
	return ctx.functionStack[len(ctx.functionStack)-1]
}

func (ctx *AnalysisContext) InPayableFunction() bool {
	fn := ctx.CurrentFunction()
	if fn == nil {
		return false
	}
	return fn.StateMutability == "payable"
}

func (ctx *AnalysisContext) CurrentFunctionHasModifier(name string) bool {
	fn := ctx.CurrentFunction()
	if fn == nil {
		return false
	}
	return fn.HasModifier(name)
}

func (ctx *AnalysisContext) CurrentContractInherits(name string) bool {
	contract := ctx.CurrentContract()
	if contract == nil {
		return false
	}
	return contract.InheritsFrom(name)
}

// ContextualVisitor context tracking ile AST'yi gezen Visitor implementasyonu.
//
// Pattern: Template Method
type ContextualVisitor struct {
	ctx     AnalysisContext
	handler NodeHandler
}

type NodeHandler interface {
	// node: ziyaret edilen node
	HandleNode(ctx *AnalysisContext, node *ASTNode) bool
}

func NewContextualVisitor(handler NodeHandler) *ContextualVisitor {
	return &ContextualVisitor{handler: handler}
}

func (cv *ContextualVisitor) Visit(node *ASTNode) bool {
	if node == nil {
		return false
	}

	// Context'e gir
	cv.enterNode(node)

	descend := cv.handler.HandleNode(&cv.ctx, node)

	_ = descend

	return descend
}

func (cv *ContextualVisitor) enterNode(node *ASTNode) {
	switch node.NodeType {
	case "ContractDefinition":
		if node.ContractDef != nil {
			cv.ctx.contractStack = append(cv.ctx.contractStack, node.ContractDef)
		}
	case "FunctionDefinition":
		if node.FunctionDef != nil {
			cv.ctx.functionStack = append(cv.ctx.functionStack, node.FunctionDef)
		}
	case "ModifierDefinition":
		if node.ModifierDef != nil {
			cv.ctx.modifierStack = append(cv.ctx.modifierStack, node.ModifierDef)
		}
	}
}

func (cv *ContextualVisitor) exitNode(node *ASTNode) {
	switch node.NodeType {
	case "ContractDefinition":
		if len(cv.ctx.contractStack) > 0 {
			cv.ctx.contractStack = cv.ctx.contractStack[:len(cv.ctx.contractStack)-1]
		}
	case "FunctionDefinition":
		if len(cv.ctx.functionStack) > 0 {
			cv.ctx.functionStack = cv.ctx.functionStack[:len(cv.ctx.functionStack)-1]
		}
	case "ModifierDefinition":
		if len(cv.ctx.modifierStack) > 0 {
			cv.ctx.modifierStack = cv.ctx.modifierStack[:len(cv.ctx.modifierStack)-1]
		}
	}
}

// WalkWithContext context tracking ile AST'yi gezdirir.
func WalkWithContext(node *ASTNode, cv *ContextualVisitor) {
	if node == nil {
		return
	}

	cv.enterNode(node)

	if cv.handler.HandleNode(&cv.ctx, node) {
		walkChildren(node, VisitorFunc(func(child *ASTNode) bool {
			WalkWithContext(child, cv)
			return false
		}))
	}

	cv.exitNode(node)
}
