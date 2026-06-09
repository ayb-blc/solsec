// internal/inheritancegraph/modifier_resolver.go

package inheritancegraph

import (
	"regexp"
	"strings"
)

// ModifierResolver resolves modifier definitions from the inheritance graph
// and classifies them by their security role through body analysis.
type ModifierResolver struct {
	graph *Graph
}

// NewModifierResolver returns a ModifierResolver for the given graph.
// The graph should have been fully built (all files scanned) before
// creating a resolver.
func NewModifierResolver(g *Graph) *ModifierResolver {
	return &ModifierResolver{graph: g}
}

// Resolve finds the definition of a modifier with the given name in the
// contract's inheritance chain. Returns nil if not found anywhere.
//
// Search order:
//  1. The contract itself
//  2. Direct parents (breadth-first, declaration order)
//  3. Well-known modifier registry (for unresolved library modifiers)
func (r *ModifierResolver) Resolve(modName string, c *ContractNode) *ModifierDef {
	if c == nil {
		if cat, ok := ClassifyByName(modName); ok {
			return &ModifierDef{
				Name:        modName,
				Category:    cat,
				IsWellKnown: true,
			}
		}
		return nil
	}

	// Check the contract itself first
	if def, ok := c.Modifiers[modName]; ok {
		return def
	}

	// Walk ancestors breadth-first
	for _, ancestor := range r.graph.GetAncestors(c) {
		if def, ok := ancestor.Modifiers[modName]; ok {
			return def
		}
	}

	// Fall back to well-known registry for external library modifiers
	if cat, ok := ClassifyByName(modName); ok {
		return &ModifierDef{
			Name:        modName,
			Category:    cat,
			IsWellKnown: true,
		}
	}

	return nil
}

// ResolveAll resolves all modifiers listed on a function and returns
// a slice of their definitions. Unresolvable modifiers are omitted.
func (r *ModifierResolver) ResolveAll(fn *FunctionNode) []*ModifierDef {
	if fn == nil {
		return nil
	}
	var defs []*ModifierDef
	for _, modName := range fn.Modifiers {
		if def := r.Resolve(modName, fn.Contract); def != nil {
			defs = append(defs, def)
		}
	}
	return defs
}

// HasAccessControl reports whether any modifier on the function
// provides access control protection.
func (r *ModifierResolver) HasAccessControl(fn *FunctionNode) bool {
	for _, def := range r.ResolveAll(fn) {
		if def.IsAccessControl() {
			return true
		}
	}
	return false
}

// HasReentrancyGuard reports whether any modifier on the function
// prevents reentrancy.
func (r *ModifierResolver) HasReentrancyGuard(fn *FunctionNode) bool {
	for _, def := range r.ResolveAll(fn) {
		if def.IsReentrancyGuard() {
			return true
		}
	}
	return false
}

// BothHaveAccessControl returns true if both functions have at least one
// access control modifier, regardless of specific name.
func (r *ModifierResolver) BothHaveAccessControl(parent, child *FunctionNode) bool {
	return r.HasAccessControl(parent) && r.HasAccessControl(child)
}

// OverrideDroppedAccessControl returns (parentDef, true) if the child
// override drops an access control modifier that was present in the parent.
// Returns (nil, false) if no regression is detected.
func (r *ModifierResolver) OverrideDroppedAccessControl(
	child *FunctionNode,
	parent *FunctionNode,
) (*ModifierDef, bool) {

	if child == nil || parent == nil || !r.HasAccessControl(parent) {
		return nil, false // parent had no AC to lose
	}
	if r.HasAccessControl(child) {
		return nil, false // child still has AC
	}

	// Find which parent modifier was the access control one
	for _, def := range r.ResolveAll(parent) {
		if def.IsAccessControl() {
			return def, true
		}
	}
	return nil, false
}

// EnrichModifiers classifies all modifier definitions in the graph.
func (g *Graph) EnrichModifiers() {
	classifier := newBodyClassifier()
	for _, c := range g.contracts {
		for _, def := range c.Modifiers {
			if def.IsWellKnown {
				continue
			}
			if def.Category == CategoryUnknown && len(def.BodyLines) > 0 {
				cat, checks := classifier.classify(def.BodyLines)
				def.Category = cat
				def.Checks = checks
			}
		}
	}
}

// Body classifier.

// bodyClassifier analyzes modifier body lines to determine category and checks.
type bodyClassifier struct {
	// Access control patterns
	msgSenderEqualsRe    *regexp.Regexp
	msgSenderNotEqualsRe *regexp.Regexp
	hasRoleRe            *regexp.Regexp
	mappingAccessRe      *regexp.Regexp

	reentrancyCheckRe *regexp.Regexp // require(!_locked), require(_status == NOT_ENTERED)
	reentrancyLockRe  *regexp.Regexp // _locked = true, _status = ENTERED

	pauseCheckRe *regexp.Regexp

	initializedCheckRe *regexp.Regexp

	timestampRe *regexp.Regexp
}

func newBodyClassifier() *bodyClassifier {
	return &bodyClassifier{
		msgSenderEqualsRe: regexp.MustCompile(
			`msg\.sender\s*==\s*\w|require\s*\(\s*msg\.sender\s*==`,
		),
		msgSenderNotEqualsRe: regexp.MustCompile(
			`msg\.sender\s*!=\s*\w|if\s*\(\s*msg\.sender\s*!=`,
		),
		hasRoleRe: regexp.MustCompile(
			`hasRole\s*\(.*msg\.sender|_checkRole\s*\(`,
		),
		mappingAccessRe: regexp.MustCompile(
			`\b(?:isAdmin|isOwner|isOperator|whitelist|authorized|approved)\s*\[\s*msg\.sender\s*\]` +
				`|_\w+\s*\[\s*msg\.sender\s*\]`,
		),
		reentrancyCheckRe: regexp.MustCompile(
			`require\s*\(\s*!\s*_?(?:locked|entered|reentrancyLock)\b` +
				`|_status\s*==\s*_NOT_ENTERED` +
				`|status\s*!=\s*ENTERED`,
		),
		reentrancyLockRe: regexp.MustCompile(
			`_?(?:locked|entered|reentrancyLock)\s*=\s*(?:true|false|ENTERED|NOT_ENTERED)` +
				`|_status\s*=\s*_ENTERED`,
		),
		pauseCheckRe: regexp.MustCompile(
			`require\s*\(\s*!?\s*(?:_paused|paused\s*\(\s*\))` +
				`|_requireNotPaused|_requirePaused`,
		),
		initializedCheckRe: regexp.MustCompile(
			`require\s*\(\s*!\s*_?initialized\b` +
				`|require\s*\(\s*_?initializing\b` +
				`|_setInitializedVersion`,
		),
		timestampRe: regexp.MustCompile(
			`block\.timestamp\s*[<>]=?\s*\w` +
				`|require.*block\.timestamp`,
		),
	}
}

// classify analyzes a modifier's body lines and returns its category
// and the specific checks found.
func (bc *bodyClassifier) classify(bodyLines []string) (ModifierCategory, []ModifierCheck) {
	var checks []ModifierCheck

	for _, line := range bodyLines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*") {
			continue
		}

		if bc.msgSenderEqualsRe.MatchString(line) {
			checks = append(checks, ModifierCheck{CheckMsgSenderEquals, trimmed})
		}
		if bc.msgSenderNotEqualsRe.MatchString(line) {
			checks = append(checks, ModifierCheck{CheckMsgSenderNotEquals, trimmed})
		}
		if bc.hasRoleRe.MatchString(line) {
			checks = append(checks, ModifierCheck{CheckMsgSenderHasRole, trimmed})
		}
		if bc.mappingAccessRe.MatchString(line) {
			checks = append(checks, ModifierCheck{CheckMsgSenderMapping, trimmed})
		}
		if bc.reentrancyCheckRe.MatchString(line) {
			checks = append(checks, ModifierCheck{CheckReentrancyFlag, trimmed})
		}
		if bc.reentrancyLockRe.MatchString(line) {
			checks = append(checks, ModifierCheck{CheckReentrancyMutation, trimmed})
		}
		if bc.pauseCheckRe.MatchString(line) {
			checks = append(checks, ModifierCheck{CheckPauseState, trimmed})
		}
		if bc.initializedCheckRe.MatchString(line) {
			checks = append(checks, ModifierCheck{CheckInitializedFlag, trimmed})
		}
		if bc.timestampRe.MatchString(line) {
			checks = append(checks, ModifierCheck{CheckTimestamp, trimmed})
		}
	}

	return deriveCategory(checks), checks
}

// deriveCategory determines the primary category from the checks found.
func deriveCategory(checks []ModifierCheck) ModifierCategory {
	if len(checks) == 0 {
		return CategoryUnknown
	}

	// Count check types
	hasAC := false
	hasReentrancy := false
	hasPause := false
	hasInit := false
	hasTime := false

	for _, c := range checks {
		switch c.Kind {
		case CheckMsgSenderEquals, CheckMsgSenderNotEquals,
			CheckMsgSenderHasRole, CheckMsgSenderMapping:
			hasAC = true
		case CheckReentrancyFlag, CheckReentrancyMutation:
			hasReentrancy = true
		case CheckPauseState:
			hasPause = true
		case CheckInitializedFlag:
			hasInit = true
		case CheckTimestamp:
			hasTime = true
		}
	}

	// Priority: access control > reentrancy > pause > initializer > time
	switch {
	case hasAC:
		return CategoryAccessControl
	case hasReentrancy:
		return CategoryReentrancyGuard
	case hasPause:
		return CategoryPauseCheck
	case hasInit:
		return CategoryInitializerOnce
	case hasTime:
		return CategoryTimeLock
	default:
		return CategoryOther
	}
}
