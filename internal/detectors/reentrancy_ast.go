package detectors

import (
	"fmt"
	"strings"

	"github.com/ayb-blc/solsec/internal/analyzer"
	"github.com/ayb-blc/solsec/internal/parser"
)

type ReentrancyASTDetector struct{}

func NewReentrancyASTDetector() *ReentrancyASTDetector {
	return &ReentrancyASTDetector{}
}

func (d *ReentrancyASTDetector) Name() string                { return "reentrancy-ast" }
func (d *ReentrancyASTDetector) Severity() analyzer.Severity { return analyzer.Critical }
func (d *ReentrancyASTDetector) Description() string {
	return "AST-based reentrancy detector: checks CEI pattern violation using precise statement ordering"
}

func (d *ReentrancyASTDetector) AnalyzeAST(unit *parser.SourceUnit, filepath string, srcMap *parser.SourceMap) ([]analyzer.Finding, error) {
	var findings []analyzer.Finding

	for _, node := range unit.Nodes {
		if node.NodeType != "ContractDefinition" || node.ContractDef == nil {
			continue
		}

		contract := node.ContractDef

		if contract.ContractKind == "library" {
			continue
		}

		contractHasGuard := contract.InheritsFrom("ReentrancyGuard")

		for _, fnNode := range contract.Nodes {
			if fnNode.NodeType != "FunctionDefinition" || fnNode.FunctionDef == nil {
				continue
			}

			fn := fnNode.FunctionDef

			if fn.Kind == "constructor" || fn.StateMutability == "pure" || fn.StateMutability == "view" {
				continue
			}

			if fn.HasModifier("nonReentrant") {
				continue
			}

			if contractHasGuard && fn.HasModifier("nonReentrant") {
				continue
			}

			if fn.Body == nil || fn.Body.Block == nil {
				continue
			}

			fnFindings := d.analyzeFunctionBody(fn, contract, filepath, srcMap)
			findings = append(findings, fnFindings...)
		}
	}

	return findings, nil
}

type statementClass int

const (
	classCheck       statementClass = iota // require, assert, revert
	classEffect                            // state variable write
	classInteraction                       // external call, ETH transfer
	classOther                             // local variable, event emit, vb.
)

type classifiedStatement struct {
	node       *parser.ASTNode
	class      statementClass
	details    string
	lineNumber int
}

// analyzeFunctionBody performs sequence analysis over function statements.
func (d *ReentrancyASTDetector) analyzeFunctionBody(
	fn *parser.FunctionDefinition,
	contract *parser.ContractDefinition,
	filepath string,
	srcMap *parser.SourceMap,
) []analyzer.Finding {

	statements := fn.Body.Block.Statements
	classified := make([]classifiedStatement, 0, len(statements))

	for _, stmt := range statements {
		class, details := d.classifyStatement(stmt, contract)
		lineNumber := 0
		if srcMap != nil {
			lineNumber = srcMap.LineOf(stmt.Src)
		}
		classified = append(classified, classifiedStatement{
			node:       stmt,
			class:      class,
			details:    details,
			lineNumber: lineNumber,
		})
	}

	firstInteractionIdx := -1
	var firstInteraction classifiedStatement

	for i, cs := range classified {
		if cs.class == classInteraction {
			firstInteractionIdx = i
			firstInteraction = cs
			break
		}
	}

	if firstInteractionIdx < 0 {
		return nil
	}

	var effectAfterInteraction *classifiedStatement

	for i := firstInteractionIdx + 1; i < len(classified); i++ {
		if classified[i].class == classEffect {
			effectAfterInteraction = &classified[i]
			break
		}
	}

	if effectAfterInteraction == nil {
		return nil
	}

	fnLine := 0
	if srcMap != nil {
		fnLine = srcMap.LineOf(fn.Src)
	}

	description := fmt.Sprintf(
		"Function '%s' in contract '%s' violates the Checks-Effects-Interactions pattern.\n\n"+
			"External interaction: %s (around line %d)\n"+
			"State change after interaction: %s (around line %d)\n\n"+
			"An attacker can re-enter this function before the state change occurs, "+
			"potentially draining funds or corrupting state.",
		fn.Name,
		contract.Name,
		firstInteraction.details,
		firstInteraction.lineNumber,
		effectAfterInteraction.details,
		effectAfterInteraction.lineNumber,
	)

	return []analyzer.Finding{
		{
			DetectorName: d.Name(),
			Title: fmt.Sprintf(
				"CEI pattern violation: reentrancy in '%s.%s'",
				contract.Name, fn.Name,
			),
			Description:    description,
			Recommendation: buildReentrancyRecommendation(fn.Name),
			Filepath:       filepath,
			Line:           fnLine,
			CodeSnippet:    fmt.Sprintf("function %s(...) %s { ... }", fn.Name, fn.Visibility),
			Severity:       analyzer.Critical,
			Confidence:     analyzer.ConfidenceHigh,
			Tags:           []string{"reentrancy", "cei-violation", "external-call", "state-change"},
		},
	}
}

func (d *ReentrancyASTDetector) classifyStatement(
	node *parser.ASTNode,
	contract *parser.ContractDefinition,
) (statementClass, string) {

	if node == nil {
		return classOther, ""
	}

	switch node.NodeType {

	case "ExpressionStatement":
		if node.ExpressionStmt == nil {
			return classOther, ""
		}
		return d.classifyExpression(node.ExpressionStmt.Expression, contract)

	case "VariableDeclarationStatement":
		// (bool success, ) = msg.sender.call{value: x}("")
		if node.VarDeclStmt != nil && node.VarDeclStmt.InitialValue != nil {
			class, details := d.classifyExpression(node.VarDeclStmt.InitialValue, contract)
			if class == classInteraction {
				return classInteraction, details
			}
		}
		return classOther, "local variable declaration"

	case "Return":
		return classOther, "return statement"

	case "EmitStatement":
		return classOther, "event emission"

	case "IfStatement":
		return classOther, "conditional statement"

	case "ForStatement", "WhileStatement":
		return classOther, "loop statement"

	default:
		return classOther, node.NodeType
	}
}

func (d *ReentrancyASTDetector) classifyExpression(
	node *parser.ASTNode,
	contract *parser.ContractDefinition,
) (statementClass, string) {

	if node == nil {
		return classOther, ""
	}

	switch node.NodeType {

	case "Assignment":
		if node.Assignment == nil {
			return classOther, ""
		}
		lhs := node.Assignment.LeftHandSide

		if d.isStateVariableWrite(lhs, contract) {
			op := node.Assignment.Operator
			varName := extractName(lhs)
			return classEffect, fmt.Sprintf("state variable write: %s %s ...", varName, op)
		}
		return classOther, "local variable assignment"

	case "FunctionCall":
		if node.FunctionCall == nil {
			return classOther, ""
		}
		return d.classifyFunctionCall(node.FunctionCall, contract)

	default:
		return classOther, ""
	}
}

// External call pattern'leri:
//
// Check pattern'leri:
//
// Internal call pattern'leri:
func (d *ReentrancyASTDetector) classifyFunctionCall(
	call *parser.FunctionCall,
	_ *parser.ContractDefinition,
) (statementClass, string) {

	expr := call.Expression
	if expr == nil {
		return classOther, ""
	}

	if expr.NodeType == "Identifier" && expr.Identifier != nil {
		name := expr.Identifier.Name
		switch name {
		case "require", "assert":
			return classCheck, fmt.Sprintf("%s(...)", name)
		case "revert":
			return classCheck, "revert(...)"
		}
	}

	if expr.NodeType == "MemberAccess" && expr.MemberAccess != nil {
		memberName := expr.MemberAccess.MemberName

		switch memberName {
		case "call":
			// ETH transfer + arbitrary external call
			receiverName := extractName(expr.MemberAccess.Expression)
			return classInteraction, fmt.Sprintf(
				"%s.call(...) — low-level external call", receiverName,
			)

		case "transfer":
			receiverName := extractName(expr.MemberAccess.Expression)
			return classInteraction, fmt.Sprintf(
				"%s.transfer(...) — ETH transfer", receiverName,
			)

		case "send":
			receiverName := extractName(expr.MemberAccess.Expression)
			return classInteraction, fmt.Sprintf(
				"%s.send(...) — ETH send", receiverName,
			)

		case "delegatecall":
			receiverName := extractName(expr.MemberAccess.Expression)
			return classInteraction, fmt.Sprintf(
				"%s.delegatecall(...) — delegatecall", receiverName,
			)

		default:
			return classOther, fmt.Sprintf(".%s(...)", memberName)
		}
	}

	return classOther, "function call"
}

// State variable write detection:
// 1. Simple assignment: stateVar = x
// 2. Mapping write: balances[addr] = x
// 3. Struct field write: user.balance = x
func (d *ReentrancyASTDetector) isStateVariableWrite(
	node *parser.ASTNode,
	contract *parser.ContractDefinition,
) bool {
	if node == nil {
		return false
	}

	stateVars := collectStateVariableNames(contract)

	baseName := extractBaseName(node)
	if baseName == "" {
		return false
	}

	_, isStateVar := stateVars[baseName]
	return isStateVar
}

func collectStateVariableNames(contract *parser.ContractDefinition) map[string]struct{} {
	names := make(map[string]struct{})
	for _, node := range contract.Nodes {
		if node.NodeType == "StateVariableDeclaration" && node.StateVarDecl != nil {
			for _, v := range node.StateVarDecl.Variables {
				names[v.Name] = struct{}{}
			}
		}
	}
	return names
}

func extractBaseName(node *parser.ASTNode) string {
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
			return extractBaseName(node.IndexAccess.BaseExpression)
		}
	case "MemberAccess":
		if node.MemberAccess != nil {
			return extractBaseName(node.MemberAccess.Expression)
		}
	}
	return ""
}

func extractName(node *parser.ASTNode) string {
	if node == nil {
		return "unknown"
	}
	switch node.NodeType {
	case "Identifier":
		if node.Identifier != nil {
			return node.Identifier.Name
		}
	case "MemberAccess":
		if node.MemberAccess != nil {
			base := extractName(node.MemberAccess.Expression)
			return base + "." + node.MemberAccess.MemberName
		}
	case "IndexAccess":
		if node.IndexAccess != nil {
			return extractName(node.IndexAccess.BaseExpression) + "[...]"
		}
	}
	return "expr"
}

func buildReentrancyRecommendation(fnName string) string {
	return strings.Join([]string{
		fmt.Sprintf("In function '%s', apply the Checks-Effects-Interactions pattern:", fnName),
		"  1. CHECKS: All require/assert statements first",
		"  2. EFFECTS: Update all state variables (balances, flags, etc.)",
		"  3. INTERACTIONS: Make external calls last",
		"",
		"Better yet, use OpenZeppelin's ReentrancyGuard:",
		"  import '@openzeppelin/contracts/security/ReentrancyGuard.sol';",
		"  contract YourContract is ReentrancyGuard {",
		fmt.Sprintf("    function %s(...) external nonReentrant {", fnName),
		"      // ...",
		"    }",
		"  }",
	}, "\n")
}
