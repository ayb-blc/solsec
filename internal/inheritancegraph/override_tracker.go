// internal/inheritancegraph/override_tracker.go

package inheritancegraph

// OverrideChain is the ordered sequence of function definitions from the
// most-derived contract to the root (first definition in the hierarchy).
//
// Example for GrandChild.withdraw:
//
//	Links[0] = GrandChild.withdraw  (most derived)
//	Links[1] = Child.withdraw
//	Links[2] = Base.withdraw        (root, IsRoot == true)
type OverrideChain struct {
	FunctionName string
	Links        []OverrideLink
}

// Root returns the link where the function was first defined.
// Returns nil if the chain is empty.
func (c *OverrideChain) Root() *OverrideLink {
	if len(c.Links) == 0 {
		return nil
	}
	return &c.Links[len(c.Links)-1]
}

func (c *OverrideChain) Tip() *OverrideLink {
	if len(c.Links) == 0 {
		return nil
	}
	return &c.Links[0]
}

func (c *OverrideChain) Depth() int { return len(c.Links) }

type OverrideLink struct {
	Function *FunctionNode
	Contract *ContractNode

	IsRoot bool

	ModifiersAdded []string

	ModifiersRemoved []string

	SecurityDelta SecurityDelta
}

// SecurityDelta describes the net change in security-relevant modifiers
// between one override and its parent definition.
type SecurityDelta struct {
	AccessControlAdded     bool
	AccessControlRemoved   bool
	ReentrancyGuardAdded   bool
	ReentrancyGuardRemoved bool
}

// IsRegression reports whether this link represents a net security regression
// (access control or reentrancy guard was dropped without replacement).
func (d SecurityDelta) IsRegression() bool {
	return d.AccessControlRemoved || d.ReentrancyGuardRemoved
}

func (d SecurityDelta) IsImprovement() bool {
	return d.AccessControlAdded || d.ReentrancyGuardAdded
}

// ModifierChange records a single modifier addition or removal in a chain.
type ModifierChange struct {
	Name     string
	Category ModifierCategory
	Action   ChangeAction
	// At is the link where the change occurred.
	At *OverrideLink
	// Parent is the link that had the previous state (nil at root).
	Parent *OverrideLink
}

// ChangeAction distinguishes additions from removals.
type ChangeAction uint8

const (
	ModifierAdded   ChangeAction = iota
	ModifierRemoved              // security-relevant change
)

func (a ChangeAction) String() string {
	if a == ModifierAdded {
		return "added"
	}
	return "removed"
}

// Override tracker.

// OverrideTracker builds and queries override chains using the project
// inheritance graph and modifier resolver.
type OverrideTracker struct {
	graph  *Graph
	modRes *ModifierResolver
	sigRes *SignatureResolver
}

// NewOverrideTracker creates a tracker for the given graph.
func NewOverrideTracker(g *Graph, modRes *ModifierResolver) *OverrideTracker {
	return &OverrideTracker{
		graph:  g,
		modRes: modRes,
		sigRes: NewSignatureResolver(),
	}
}

// GetChain returns the full OverrideChain for a function in the given contract.
// If the function is not defined in the contract, returns an empty chain.
//
// The chain is built top-down (most-derived first) using the graph's
// ancestor traversal and selector-based function matching.
func (t *OverrideTracker) GetChain(
	c *ContractNode,
	funcName string,
) *OverrideChain {

	chain := &OverrideChain{FunctionName: funcName}

	// Collect every ancestor that defines this function, in order
	// from most-derived (c) to most-base.
	var raw []OverrideLink

	// Include the contract itself if it defines the function.
	if fn, ok := c.Functions[funcName]; ok {
		raw = append(raw, OverrideLink{Function: fn, Contract: c})
	}

	// Walk ancestors. GetAncestors returns breadth-first from nearest.
	for _, ancestor := range t.graph.GetAncestors(c) {
		fn, ok := ancestor.Functions[funcName]
		if !ok {
			continue
		}
		// Selector-based match: uint == uint256 etc.
		if len(raw) > 0 {
			tipFn := raw[0].Function
			if !t.selectorsMatch(tipFn, fn) {
				continue // different overload, not the same chain
			}
		}
		raw = append(raw, OverrideLink{Function: fn, Contract: ancestor})
	}

	if len(raw) == 0 {
		return chain
	}

	// Mark the root
	raw[len(raw)-1].IsRoot = true

	// Compute modifier diffs and security deltas between consecutive links.
	// We go from base to tip (reverse), so parent is always raw[i+1].
	for i := range raw {
		link := &raw[i]

		// The "parent" in the override sense is the link closer to the base.
		var parentLink *OverrideLink
		if i < len(raw)-1 {
			parentLink = &raw[i+1]
		}

		if parentLink != nil {
			link.ModifiersAdded, link.ModifiersRemoved = diffModifiers(
				link.Function.Modifiers,
				parentLink.Function.Modifiers,
			)
			link.SecurityDelta = t.computeDelta(link, parentLink)
		}

		chain.Links = append(chain.Links, *link)
	}

	return chain
}

// FindModifierChanges returns all modifier additions and removals in the chain,
// ordered from root to tip (base to most-derived).
func (t *OverrideTracker) FindModifierChanges(chain *OverrideChain) []ModifierChange {
	var changes []ModifierChange

	// Walk from tip to root; changes are computed at each link vs its parent.
	for i := range chain.Links {
		link := &chain.Links[i]
		var parentLink *OverrideLink
		if i < len(chain.Links)-1 {
			parentLink = &chain.Links[i+1]
		}

		for _, name := range link.ModifiersAdded {
			def := t.modRes.Resolve(name, link.Contract)
			cat := CategoryUnknown
			if def != nil {
				cat = def.Category
			}
			changes = append(changes, ModifierChange{
				Name:     name,
				Category: cat,
				Action:   ModifierAdded,
				At:       link,
				Parent:   parentLink,
			})
		}

		for _, name := range link.ModifiersRemoved {
			def := t.resolveInAncestors(name, link.Contract)
			cat := CategoryUnknown
			if def != nil {
				cat = def.Category
			}
			changes = append(changes, ModifierChange{
				Name:     name,
				Category: cat,
				Action:   ModifierRemoved,
				At:       link,
				Parent:   parentLink,
			})
		}
	}

	return changes
}

// FirstAccessControlRegression returns the OverrideLink where access control
// was dropped for the first time in the chain, along with the modifier that
// was removed. Returns nil if no regression exists.
func (t *OverrideTracker) FirstAccessControlRegression(
	chain *OverrideChain,
) (*OverrideLink, *ModifierDef) {

	for i := range chain.Links {
		link := &chain.Links[i]
		if !link.SecurityDelta.AccessControlRemoved {
			continue
		}
		// Find which removed modifier was access control
		for _, name := range link.ModifiersRemoved {
			def := t.resolveInAncestors(name, link.Contract)
			if def != nil && def.IsAccessControl() {
				return link, def
			}
		}
	}
	return nil, nil
}

// HasConsistentAccessControl reports whether access control is present
// at EVERY level of the chain (no regression anywhere).
func (t *OverrideTracker) HasConsistentAccessControl(chain *OverrideChain) bool {
	for i := range chain.Links {
		link := &chain.Links[i]
		if !t.modRes.HasAccessControl(link.Function) {
			// Root without AC is fine if no ancestor had it either.
			if !link.IsRoot {
				return false
			}
		}
	}
	return true
}

// AnyLinkHasReentrancyGuard reports whether any override in the chain
// has reentrancy protection. Used by reentrancy detector.
func (t *OverrideTracker) AnyLinkHasReentrancyGuard(chain *OverrideChain) bool {
	for i := range chain.Links {
		if t.modRes.HasReentrancyGuard(chain.Links[i].Function) {
			return true
		}
	}
	return false
}

// Project override index.

// ProjectOverrideIndex pre-computes override chains for all virtual and
// override functions in the project. Build once, query many times.
type ProjectOverrideIndex struct {
	tracker *OverrideTracker

	// chains[contractKey][funcName] = precomputed chain
	chains map[string]map[string]*OverrideChain
}

// BuildIndex pre-computes override chains for every function that appears
// in an override chain anywhere in the project.
func BuildIndex(g *Graph, modRes *ModifierResolver) *ProjectOverrideIndex {
	tracker := NewOverrideTracker(g, modRes)
	idx := &ProjectOverrideIndex{
		tracker: tracker,
		chains:  make(map[string]map[string]*OverrideChain),
	}

	for _, c := range g.AllContracts() {
		contractKey := c.Filepath + "::" + c.Name
		idx.chains[contractKey] = make(map[string]*OverrideChain)

		for funcName := range c.Functions {
			chain := tracker.GetChain(c, funcName)
			if chain.Depth() > 1 { // only store if there's an actual override
				idx.chains[contractKey][funcName] = chain
			}
		}
	}

	return idx
}

// GetChain returns the pre-computed chain for a function in a contract.
// Returns nil if the function has no override chain.
func (idx *ProjectOverrideIndex) GetChain(
	c *ContractNode,
	funcName string,
) *OverrideChain {
	key := c.Filepath + "::" + c.Name
	if m, ok := idx.chains[key]; ok {
		return m[funcName]
	}
	return nil
}

// FindAllRegressions returns all access control regressions across the
// entire project: every place a function override drops access control.
func (idx *ProjectOverrideIndex) FindAllRegressions() []RegressionReport {
	var reports []RegressionReport
	seen := make(map[string]bool)

	for _, chainsByFunc := range idx.chains {
		for _, chain := range chainsByFunc {
			link, def := idx.tracker.FirstAccessControlRegression(chain)
			if link == nil {
				continue
			}
			key := regressionKey(link)
			if seen[key] {
				continue
			}
			seen[key] = true
			reports = append(reports, RegressionReport{
				Chain:          chain,
				RegressionLink: link,
				DroppedDef:     def,
			})
		}
	}

	return reports
}

// RegressionReport describes a detected security regression in an override chain.
type RegressionReport struct {
	Chain          *OverrideChain
	RegressionLink *OverrideLink
	DroppedDef     *ModifierDef
}

// Helpers.

// diffModifiers computes which modifier names were added and removed
// when going from parent modifiers to child modifiers.
//
// added = in child but not in parent
// removed = in parent but not in child
func diffModifiers(childMods, parentMods []string) (added, removed []string) {
	childSet := stringsToSet(childMods)
	parentSet := stringsToSet(parentMods)

	for name := range childSet {
		if !parentSet[name] {
			added = append(added, name)
		}
	}
	for name := range parentSet {
		if !childSet[name] {
			removed = append(removed, name)
		}
	}
	return added, removed
}

func stringsToSet(ss []string) map[string]bool {
	m := make(map[string]bool, len(ss))
	for _, s := range ss {
		m[s] = true
	}
	return m
}

// computeDelta determines what security changed between link and its parent.
func (t *OverrideTracker) computeDelta(link, parent *OverrideLink) SecurityDelta {
	var d SecurityDelta
	accessControlAdded := false
	accessControlRemoved := false
	reentrancyGuardAdded := false
	reentrancyGuardRemoved := false

	for _, name := range link.ModifiersAdded {
		def := t.modRes.Resolve(name, link.Contract)
		if def == nil {
			continue
		}
		switch def.Category {
		case CategoryAccessControl:
			accessControlAdded = true
		case CategoryReentrancyGuard:
			reentrancyGuardAdded = true
		}
	}

	for _, name := range link.ModifiersRemoved {
		// Modifier was in the parent; resolve from parent contract.
		def := t.modRes.Resolve(name, parent.Contract)
		if def == nil {
			// Try well-known registry as fallback
			if cat, ok := ClassifyByName(name); ok {
				switch cat {
				case CategoryAccessControl:
					accessControlRemoved = true
				case CategoryReentrancyGuard:
					reentrancyGuardRemoved = true
				}
			}
			continue
		}
		switch def.Category {
		case CategoryAccessControl:
			accessControlRemoved = true
		case CategoryReentrancyGuard:
			reentrancyGuardRemoved = true
		}
	}

	d.AccessControlAdded = accessControlAdded
	d.ReentrancyGuardAdded = reentrancyGuardAdded
	d.AccessControlRemoved = accessControlRemoved && !accessControlAdded
	d.ReentrancyGuardRemoved = reentrancyGuardRemoved && !reentrancyGuardAdded
	return d
}

func regressionKey(link *OverrideLink) string {
	if link == nil || link.Function == nil || link.Contract == nil {
		return ""
	}
	selector := link.Function.Canonical
	if selector == "" {
		selector = link.Function.Name
	}
	return link.Contract.Filepath + "::" + link.Contract.Name + "::" + selector
}

// selectorsMatch reports whether two FunctionNodes represent the same
// function signature (same selector after type normalization).
func (t *OverrideTracker) selectorsMatch(a, b *FunctionNode) bool {
	// If both have pre-computed selectors (from EnrichFunctions), use them.
	if a.Selector != ([4]byte{}) && b.Selector != ([4]byte{}) {
		return a.Selector == b.Selector
	}
	return a.Name == b.Name
}

// resolveInAncestors looks up a modifier name in a contract's ancestor chain.
// Used when the modifier is defined in a parent, not the contract itself.
func (t *OverrideTracker) resolveInAncestors(
	name string,
	c *ContractNode,
) *ModifierDef {
	for _, ancestor := range t.graph.GetAncestors(c) {
		if def, ok := ancestor.Modifiers[name]; ok {
			return def
		}
	}
	if cat, ok := ClassifyByName(name); ok {
		return &ModifierDef{Name: name, Category: cat, IsWellKnown: true}
	}
	return nil
}
