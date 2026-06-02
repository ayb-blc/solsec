package parser

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type VyperParser struct {
	binaryPath string
}

func NewVyperParser(binaryPath string) *VyperParser {
	if binaryPath == "" {
		binaryPath = "vyper"
	}
	return &VyperParser{binaryPath: binaryPath}
}

func (p *VyperParser) Language() Language { return LanguageVyper }

func (p *VyperParser) CanParse(path string) bool {
	return filepath.Ext(path) == ".vy"
}

func (p *VyperParser) IsAvailable() bool {
	_, err := exec.LookPath(p.binaryPath)
	return err == nil
}

func (p *VyperParser) Parse(path string) (*UnifiedAST, error) {
	if !p.CanParse(path) {
		return nil, fmt.Errorf("vyper parser cannot parse %q", path)
	}
	out, err := exec.Command(p.binaryPath, "-f", "ast", path).Output()
	if err != nil {
		return nil, err
	}
	var module VyperModule
	if err := json.Unmarshal(out, &module); err != nil {
		return nil, err
	}
	ast := p.unify(path, &module)
	if content, err := os.ReadFile(path); err == nil {
		ast.Lines = strings.Split(string(content), "\n")
	}
	return ast, nil
}

func (p *VyperParser) unify(path string, module *VyperModule) *UnifiedAST {
	contract := &UnifiedContract{
		Name:    filepath.Base(path),
		Kind:    "module",
		Parents: nil,
	}
	if module != nil {
		for _, node := range module.Body {
			if node == nil {
				continue
			}
			switch {
			case node.IsStateVar():
				contract.StateVars = append(contract.StateVars, &UnifiedStateVariable{
					Name: node.TargetName(),
					Line: node.StartLine(),
					Raw:  node,
				})
			case node.IsFunctionDef():
				contract.Functions = append(contract.Functions, p.unifyFunction(node))
			}
		}
	}
	return &UnifiedAST{
		Language:  LanguageVyper,
		Filepath:  path,
		Contracts: []*UnifiedContract{contract},
		Vyper:     module,
	}
}

func (p *VyperParser) unifyFunction(node *VyperNode) *UnifiedFunction {
	fn := &UnifiedFunction{
		Name:       node.Name,
		Visibility: vyperVisibility(node),
		Mutability: vyperMutability(node),
		Line:       node.StartLine(),
		Raw:        node,
	}
	for _, dec := range node.Decorators {
		if name := vyperDecoratorName(dec); name != "" {
			fn.Modifiers = append(fn.Modifiers, name)
		}
	}
	if node.Args != nil {
		for _, arg := range node.Args.Args {
			fn.Parameters = append(fn.Parameters, &UnifiedVariable{
				Name: arg.Name,
				Line: arg.StartLine(),
				Raw:  arg,
			})
		}
	}
	for _, stmt := range node.Body {
		fn.Body = append(fn.Body, &UnifiedStatement{
			Kind:                 stmt.ASTType,
			Line:                 stmt.StartLine(),
			ContainsExternalCall: vyperContainsExternalCall(stmt),
			WritesState:          vyperWritesState(stmt),
			Raw:                  stmt,
		})
	}
	return fn
}

func vyperVisibility(node *VyperNode) string {
	if node.HasDecorator("internal") || node.IsInternal {
		return "internal"
	}
	return "external"
}

func vyperMutability(node *VyperNode) string {
	switch {
	case node.HasDecorator("view") || node.IsView:
		return "view"
	case node.HasDecorator("pure"):
		return "pure"
	case node.HasDecorator("payable") || node.IsPayable:
		return "payable"
	default:
		return "nonpayable"
	}
}

func vyperDecoratorName(node *VyperNode) string {
	if node == nil {
		return ""
	}
	if node.ASTType == "Call" && node.Func != nil {
		if node.Func.ID != "" {
			return node.Func.ID
		}
		return node.Func.Attr
	}
	if node.ID != "" {
		return node.ID
	}
	return node.Attr
}

func vyperContainsExternalCall(node *VyperNode) bool {
	if node == nil {
		return false
	}
	if node.IsRawCall() {
		return true
	}
	for _, child := range vyperChildren(node) {
		if vyperContainsExternalCall(child) {
			return true
		}
	}
	return false
}

func vyperWritesState(node *VyperNode) bool {
	if node == nil {
		return false
	}
	if (node.ASTType == "Assign" || node.ASTType == "AugAssign" || node.ASTType == "AnnAssign") &&
		viperNodeTouchesSelf(node.Target) {
		return true
	}
	for _, target := range node.Targets {
		if viperNodeTouchesSelf(target) {
			return true
		}
	}
	for _, child := range vyperChildren(node) {
		if vyperWritesState(child) {
			return true
		}
	}
	return false
}

func viperNodeTouchesSelf(node *VyperNode) bool {
	if node == nil {
		return false
	}
	if node.ASTType == "Name" && node.ID == "self" {
		return true
	}
	return viperNodeTouchesSelf(node.Target) ||
		viperNodeTouchesSelf(node.Func) ||
		viperNodeTouchesSelf(node.Left) ||
		viperNodeTouchesSelf(node.Right)
}

func vyperChildren(node *VyperNode) []*VyperNode {
	if node == nil {
		return nil
	}
	children := []*VyperNode{
		node.Target, node.Annotation, node.Value, node.Slice, node.Func,
		node.Test, node.Iter, node.Left, node.Right, node.Keyword,
	}
	children = append(children, node.Body...)
	children = append(children, node.Decorators...)
	children = append(children, node.CallArgs...)
	children = append(children, node.Keywords...)
	children = append(children, node.ThenBB...)
	children = append(children, node.ElseBB...)
	children = append(children, node.Targets...)
	children = append(children, node.Comparators...)
	return children
}
