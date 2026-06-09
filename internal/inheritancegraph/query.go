// internal/inheritancegraph/query.go

package inheritancegraph

// GetAncestors returns all ancestors of c in breadth-first order.
// Direct parents come before grandparents.
// The returned slice never contains c itself.
func (g *Graph) GetAncestors(c *ContractNode) []*ContractNode {
	seen := make(map[*ContractNode]bool)
	var result []*ContractNode
	queue := append([]*ContractNode{}, c.Parents...)

	for len(queue) > 0 {
		node := queue[0]
		queue = queue[1:]
		if seen[node] {
			continue
		}
		seen[node] = true
		result = append(result, node)
		queue = append(queue, node.Parents...)
	}
	return result
}

// GetDescendants returns all contracts that (transitively) inherit from c.
func (g *Graph) GetDescendants(c *ContractNode) []*ContractNode {
	seen := make(map[*ContractNode]bool)
	var result []*ContractNode
	queue := append([]*ContractNode{}, c.Children...)

	for len(queue) > 0 {
		node := queue[0]
		queue = queue[1:]
		if seen[node] {
			continue
		}
		seen[node] = true
		result = append(result, node)
		queue = append(queue, node.Children...)
	}
	return result
}

// FindFunctionInAncestors walks the ancestor chain looking for the first
// contract that defines a function with the given name.
// If both child and parent functions have selectors, selector matching is used
// so overloads and aliases like uint/uint256 are handled accurately.
// Returns (function, contract) or (nil, nil) if not found.
func (g *Graph) FindFunctionInAncestors(
	c *ContractNode,
	funcName string,
) (*FunctionNode, *ContractNode) {

	var childFn *FunctionNode
	if c != nil {
		childFn = c.Functions[funcName]
	}

	for _, ancestor := range g.GetAncestors(c) {
		if fn, ok := ancestor.Functions[funcName]; ok {
			if childFn != nil && childFn.Selector != ([4]byte{}) && fn.Selector != ([4]byte{}) {
				if childFn.Selector == fn.Selector {
					return fn, ancestor
				}
				continue
			}
			return fn, ancestor
		}
	}
	return nil, nil
}

// SelectorCollisionFunction identifies one function participating in a selector
// collision.
type SelectorCollisionFunction struct {
	Function *FunctionNode
	Contract *ContractNode
}

// SelectorCollision describes multiple canonical signatures sharing one
// 4-byte ABI selector.
type SelectorCollision struct {
	Selector  [4]byte
	Functions []SelectorCollisionFunction
}

// SelectorCollisions finds project functions with the same 4-byte selector but
// different canonical forms.
func (g *Graph) SelectorCollisions() []SelectorCollision {
	bySelector := make(map[[4]byte][]SelectorCollisionFunction)
	for _, c := range g.contracts {
		for _, fn := range c.Functions {
			if fn.Selector == ([4]byte{}) {
				continue
			}
			bySelector[fn.Selector] = append(bySelector[fn.Selector], SelectorCollisionFunction{
				Function: fn,
				Contract: c,
			})
		}
	}

	var collisions []SelectorCollision
	for selector, entries := range bySelector {
		if len(entries) < 2 {
			continue
		}
		first := entries[0].Function.Canonical
		for _, entry := range entries[1:] {
			if entry.Function.Canonical != first {
				collisions = append(collisions, SelectorCollision{
					Selector:  selector,
					Functions: entries,
				})
				break
			}
		}
	}
	return collisions
}

// OverrideEntry describes one function definition in an override chain.
type OverrideEntry struct {
	Function *FunctionNode
	Contract *ContractNode
}

// GetOverrideChain returns the chain of function definitions from the
// given contract up to the root of the inheritance tree.
// Each entry is (function, contract) where function is the definition
// at that level, or nil if that ancestor does not define the function.
func (g *Graph) GetOverrideChain(
	c *ContractNode,
	funcName string,
) []OverrideEntry {

	var chain []OverrideEntry

	// Include the definition in c itself (if any)
	if fn, ok := c.Functions[funcName]; ok {
		chain = append(chain, OverrideEntry{fn, c})
	}

	// Walk ancestors
	for _, ancestor := range g.GetAncestors(c) {
		if fn, ok := ancestor.Functions[funcName]; ok {
			chain = append(chain, OverrideEntry{fn, ancestor})
		}
	}

	return chain
}

// InheritsFrom reports whether c has contractName anywhere in its ancestor chain.
// Case-sensitive.
func (g *Graph) InheritsFrom(c *ContractNode, contractName string) bool {
	for _, ancestor := range g.GetAncestors(c) {
		if ancestor.Name == contractName {
			return true
		}
	}
	return false
}

// GetAllFunctions returns the effective function set for a contract,
// including inherited functions. Functions defined in c override
// those from parent contracts (same as Solidity resolution).
// The returned map key is function name.
func (g *Graph) GetAllFunctions(c *ContractNode) map[string]*FunctionNode {
	result := make(map[string]*FunctionNode)

	// Walk ancestors from most-distant to nearest so that
	// closer definitions override farther ones.
	ancestors := g.GetAncestors(c)
	for i := len(ancestors) - 1; i >= 0; i-- {
		for name, fn := range ancestors[i].Functions {
			result[name] = fn
		}
	}

	// Own functions override everything.
	for name, fn := range c.Functions {
		result[name] = fn
	}

	return result
}

// IsBaseContract reports whether any other contract in the project
// inherits from c.
func (g *Graph) IsBaseContract(c *ContractNode) bool {
	return len(c.Children) > 0
}

// OverrideDroppedAccessControl checks whether a function override in child
// removes an access control modifier that was present in a parent.
// Returns (parentFunc, parentContract, true) if a regression is found.
func (g *Graph) OverrideDroppedAccessControl(
	child *ContractNode,
	funcName string,
) (*FunctionNode, *ContractNode, bool) {

	childFn, ok := child.Functions[funcName]
	if !ok || !childFn.IsOverride {
		return nil, nil, false
	}
	if childFn.HasAccessControl() {
		return nil, nil, false
	}

	parentFn, parentContract := g.FindFunctionInAncestors(child, funcName)
	if parentFn == nil {
		return nil, nil, false
	}
	if !parentFn.HasAccessControl() {
		return nil, nil, false
	}

	return parentFn, parentContract, true
}
