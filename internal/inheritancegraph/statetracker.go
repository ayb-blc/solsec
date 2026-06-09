// internal/inheritancegraph/statetracker.go

package inheritancegraph

import (
	"regexp"
	"strings"
)

// OpKind is the type of a single operation in a function body.
type OpKind uint8

const (
	OpRead         OpKind = iota // read of a state variable
	OpWrite                      // write to a state variable
	OpExternalCall               // call to an external address
	OpInternalCall               // call to an internal/private function
)

func (k OpKind) String() string {
	switch k {
	case OpRead:
		return "READ"
	case OpWrite:
		return "WRITE"
	case OpExternalCall:
		return "EXTERNAL_CALL"
	case OpInternalCall:
		return "INTERNAL_CALL"
	default:
		return "?"
	}
}

// StateAccess describes a single read from or write to a state variable.
type StateAccess struct {
	VarName   string // base variable name, e.g. "balances"
	FullExpr  string // full expression, e.g. "balances[msg.sender]"
	Line      string // raw trimmed source line
	LineNum   int
	IsMapping bool   // true for "balances[key]" patterns
	MapKey    string // the key string if IsMapping
}

// CallOp describes a call site (external or internal).
type CallOp struct {
	Callee     string // receiver, e.g. "msg.sender", "token", "IERC20(addr)"
	Method     string // method name, e.g. "call", "transfer", "flashLoan"
	IsExternal bool
	Line       string
	LineNum    int
}

// StateOp is a single ordered operation in a function body.
// Exactly one of Access and Call is non-nil.
type StateOp struct {
	Kind    OpKind
	Access  *StateAccess // non-nil for OpRead / OpWrite
	Call    *CallOp      // non-nil for OpExternalCall / OpInternalCall
	LineNum int
}

// CEIViolation is a state write that occurs AFTER an external call;
// the classic reentrancy pattern (Checks-Effects-Interactions violated).
type CEIViolation struct {
	// ExternalCall is the interaction that precedes the write.
	ExternalCall *CallOp
	// WriteAfter is the state write that follows the call.
	WriteAfter *StateAccess
	// LinesBetween is the distance between call and write.
	LinesBetween int
}

// FunctionStateMap holds the ordered state analysis for a single function.
type FunctionStateMap struct {
	Function *FunctionNode
	Contract *ContractNode

	// KnownVars is the set of state variable names accessible in this
	// function (declared in the contract or any ancestor).
	KnownVars map[string]StateVar

	// Ops is the ordered sequence of state operations and calls.
	Ops []StateOp

	// Convenience slices derived from Ops.
	Reads    []StateAccess
	Writes   []StateAccess
	ExtCalls []CallOp
}

// HasWriteBeforeCall reports whether at least one state write occurs
// before any external call. Used to verify CEI compliance.
func (m *FunctionStateMap) HasWriteBeforeCall() bool {
	for _, op := range m.Ops {
		if op.Kind == OpWrite {
			return true
		}
		if op.Kind == OpExternalCall {
			return false
		}
	}
	return false
}

// HasWriteAfterCall reports whether any state write occurs after an
// external call, the necessary condition for reentrancy vulnerability.
func (m *FunctionStateMap) HasWriteAfterCall() bool {
	seenCall := false
	for _, op := range m.Ops {
		if op.Kind == OpExternalCall {
			seenCall = true
		}
		if op.Kind == OpWrite && seenCall {
			return true
		}
	}
	return false
}

// FindCEIViolations returns all state writes that occur after an external
// call in this function. Each entry pairs the call with the write that
// follows it.
func (m *FunctionStateMap) FindCEIViolations() []CEIViolation {
	var violations []CEIViolation

	for i, op := range m.Ops {
		if op.Kind != OpExternalCall {
			continue
		}
		// Look ahead for state writes that follow this call
		for j := i + 1; j < len(m.Ops); j++ {
			subsequent := m.Ops[j]
			if subsequent.Kind == OpWrite {
				violations = append(violations, CEIViolation{
					ExternalCall: op.Call,
					WriteAfter:   subsequent.Access,
					LinesBetween: subsequent.LineNum - op.LineNum,
				})
			}
		}
	}

	return violations
}

// WritesTo reports whether the function writes to the named state variable.
func (m *FunctionStateMap) WritesTo(varName string) bool {
	for _, w := range m.Writes {
		if w.VarName == varName {
			return true
		}
	}
	return false
}

// WritesPrivilegedState reports whether the function writes to variables
// that are typically privileged (owner, admin, treasury, oracle, etc.).
func (m *FunctionStateMap) WritesPrivilegedState() (bool, string) {
	privileged := []string{
		"owner", "_owner", "admin", "_admin",
		"governance", "controller", "operator",
		"token", "treasury", "oracle", "implementation",
		"vault", "pool", "router", "factory", "weth",
	}
	for _, w := range m.Writes {
		name := strings.ToLower(w.VarName)
		for _, p := range privileged {
			if strings.Contains(name, p) {
				return true, w.VarName
			}
		}
	}
	return false, ""
}

// StateTracker.

// StateTracker builds FunctionStateMaps for functions in the project.
// It uses the inheritance graph to resolve state variable names from
// the full ancestor chain.
type StateTracker struct {
	graph *Graph
}

// NewStateTracker creates a StateTracker for the given graph.
func NewStateTracker(g *Graph) *StateTracker {
	return &StateTracker{graph: g}
}

// Analyze produces a FunctionStateMap for the given function.
func (t *StateTracker) Analyze(fn *FunctionNode, c *ContractNode) *FunctionStateMap {
	m := &FunctionStateMap{
		Function:  fn,
		Contract:  c,
		KnownVars: t.collectKnownVars(c),
	}

	parser := newLineParser()
	for i, line := range fn.BodyLines {
		lineNum := fn.LineNumber + i + 1
		trimmed := strings.TrimSpace(line)

		// Skip blank lines and comments
		if trimmed == "" ||
			strings.HasPrefix(trimmed, "//") ||
			strings.HasPrefix(trimmed, "*") {
			continue
		}

		// Detect external calls first (order matters for CEI)
		if calls := parser.extractExternalCalls(line, lineNum); len(calls) > 0 {
			for _, call := range calls {
				m.Ops = append(m.Ops, StateOp{
					Kind: OpExternalCall, Call: &call, LineNum: lineNum,
				})
				m.ExtCalls = append(m.ExtCalls, call)
			}
			continue
		}

		// Detect state writes
		if writes := parser.extractWrites(line, lineNum, m.KnownVars); len(writes) > 0 {
			for _, w := range writes {
				m.Ops = append(m.Ops, StateOp{
					Kind: OpWrite, Access: &w, LineNum: lineNum,
				})
				m.Writes = append(m.Writes, w)
			}
		}

		// Detect state reads (only for known state vars)
		if reads := parser.extractReads(line, lineNum, m.KnownVars); len(reads) > 0 {
			for _, r := range reads {
				m.Ops = append(m.Ops, StateOp{
					Kind: OpRead, Access: &r, LineNum: lineNum,
				})
				m.Reads = append(m.Reads, r)
			}
		}
	}

	return m
}

// AnalyzeProject builds FunctionStateMaps for every function in the project.
func (t *StateTracker) AnalyzeProject() map[string]*FunctionStateMap {
	result := make(map[string]*FunctionStateMap)
	for _, c := range t.graph.AllContracts() {
		for _, fn := range c.Functions {
			key := c.Filepath + "::" + c.Name + "::" + fn.Name
			result[key] = t.Analyze(fn, c)
		}
	}
	return result
}

// collectKnownVars gathers all state variable names accessible from a
// contract, including those inherited from ancestors.
func (t *StateTracker) collectKnownVars(c *ContractNode) map[string]StateVar {
	vars := make(map[string]StateVar)

	// Ancestors first (lower priority)
	for _, ancestor := range t.graph.GetAncestors(c) {
		for _, sv := range ancestor.StateVars {
			vars[sv.Name] = sv
		}
	}
	// Own vars override ancestor vars
	for _, sv := range c.StateVars {
		vars[sv.Name] = sv
	}
	return vars
}

// lineParser extracts operations from individual source lines.

// lineParser extracts operations from individual source lines.
type lineParser struct {
	// External call patterns
	dotCallRe     *regexp.Regexp // .call{value:...}(...) or .call(...)
	dotTransferRe *regexp.Regexp // .transfer(...) or .send(...)
	dotSendRe     *regexp.Regexp
	interfaceRe   *regexp.Regexp // IToken(addr).transfer(...)
	callMethodRe  *regexp.Regexp // general .method( external heuristic

	// Write patterns
	simpleWriteRe   *regexp.Regexp // var = expr
	compoundWriteRe *regexp.Regexp // var += / -= / etc.
	mappingWriteRe  *regexp.Regexp // var[key] = expr
	incDecRe        *regexp.Regexp // var++ / var--

	// Mapping access pattern (for VarName extraction)
	mappingAccessRe *regexp.Regexp
}

func newLineParser() *lineParser {
	return &lineParser{
		dotCallRe: regexp.MustCompile(
			`\.\s*call\s*(?:\{[^}]*\})?\s*\(`,
		),
		dotTransferRe: regexp.MustCompile(
			`\.\s*transfer\s*\(`,
		),
		dotSendRe: regexp.MustCompile(
			`\.\s*send\s*\(`,
		),
		// Interface-style: IERC20(token).transfer(...)
		interfaceRe: regexp.MustCompile(
			`\b[A-Z]\w*\s*\(\s*\w[\w.]*\s*\)\s*\.\s*(\w+)\s*\(`,
		),
		// Any .method( call that isn't a known safe pattern
		callMethodRe: regexp.MustCompile(
			`\b(\w[\w.]*)\s*\.\s*(\w+)\s*\(`,
		),

		// var = value (but not ==, !=, <=, >=)
		simpleWriteRe: regexp.MustCompile(
			`^\s*(\w+)\s*=\s*[^=]`,
		),
		// var += value etc.
		compoundWriteRe: regexp.MustCompile(
			`\b(\w+)\s*(?:\+=|-=|\*=|/=|%=|&=|\|=|\^=|<<=|>>=)`,
		),
		// var[key] = value
		mappingWriteRe: regexp.MustCompile(
			`\b(\w+)\s*\[\s*([^\]]+)\s*\]\s*(?:\[.*\]\s*)?(?:=|[+\-*/%&|^]=|<<=|>>=)\s*[^=]`,
		),
		// var++ or var--
		incDecRe: regexp.MustCompile(
			`\b(\w+)\s*(?:\+\+|--)`,
		),
		// mapping[key] access (read or write)
		mappingAccessRe: regexp.MustCompile(
			`\b(\w+)\s*\[\s*([^\]]+)\s*\]`,
		),
	}
}

// isKnownSafeCall returns true for calls that don't create reentrancy risk.
var knownSafeCallMethods = map[string]bool{
	// OZ SafeERC20 and similar revert on failure and have lower callback risk.
	"safeTransfer": true, "safeTransferFrom": true, "safeApprove": true,
	"safeIncreaseAllowance": true, "safeDecreaseAllowance": true,
	// Emit events are not calls.
	"emit": true,
	// Pure view calls
	"balanceOf": true, "allowance": true, "totalSupply": true,
	"decimals": true, "symbol": true, "name": true,
	// Reverts and requires are not external calls.
	"require": true, "revert": true, "assert": true,
}

func (p *lineParser) extractExternalCalls(line string, lineNum int) []CallOp {
	var calls []CallOp
	trimmed := strings.TrimSpace(line)

	// .call{...}(...) is always external and high-risk.
	if p.dotCallRe.MatchString(line) {
		callee, method := extractCalleeMethod(line, "call")
		calls = append(calls, CallOp{
			Callee: callee, Method: "call",
			IsExternal: true, Line: trimmed, LineNum: lineNum,
		})
		_ = method
		return calls // .call is unambiguous; return immediately.
	}

	// .transfer() or .send() on ETH (not ERC20 safeTransfer)
	if p.dotTransferRe.MatchString(line) || p.dotSendRe.MatchString(line) {
		if !strings.Contains(line, "safeTransfer") {
			method := "transfer"
			if p.dotSendRe.MatchString(line) {
				method = "send"
			}
			callee, _ := extractCalleeMethod(line, method)
			calls = append(calls, CallOp{
				Callee: callee, Method: method,
				IsExternal: true, Line: trimmed, LineNum: lineNum,
			})
		}
	}

	// Interface-style calls: IToken(addr).method(...)
	if m := p.interfaceRe.FindStringSubmatch(line); m != nil {
		methodName := m[1]
		if !knownSafeCallMethods[methodName] {
			calls = append(calls, CallOp{
				Callee: "interface", Method: methodName,
				IsExternal: true, Line: trimmed, LineNum: lineNum,
			})
		}
	}

	return calls
}

func (p *lineParser) extractWrites(
	line string,
	lineNum int,
	knownVars map[string]StateVar,
) []StateAccess {

	var accesses []StateAccess
	trimmed := strings.TrimSpace(line)

	// Skip comments, require, emit, return
	if strings.HasPrefix(trimmed, "//") ||
		strings.HasPrefix(trimmed, "emit ") ||
		strings.HasPrefix(trimmed, "require(") ||
		strings.HasPrefix(trimmed, "revert") ||
		strings.HasPrefix(trimmed, "return ") {
		return nil
	}

	// Mapping write: balances[msg.sender] -= amount
	if m := p.mappingWriteRe.FindStringSubmatch(line); m != nil {
		varName := m[1]
		mapKey := strings.TrimSpace(m[2])
		if _, ok := knownVars[varName]; ok {
			accesses = append(accesses, StateAccess{
				VarName:   varName,
				FullExpr:  varName + "[" + mapKey + "]",
				Line:      trimmed,
				LineNum:   lineNum,
				IsMapping: true,
				MapKey:    mapKey,
			})
		}
	}

	// Compound assignment: totalSupply += amount
	if m := p.compoundWriteRe.FindStringSubmatch(line); m != nil {
		varName := m[1]
		if _, ok := knownVars[varName]; ok {
			if !alreadyCaptured(accesses, varName) {
				accesses = append(accesses, StateAccess{
					VarName: varName, FullExpr: trimmed,
					Line: trimmed, LineNum: lineNum,
				})
			}
		}
	}

	// Simple assignment: owner = newOwner (but not ==)
	if m := p.simpleWriteRe.FindStringSubmatch(line); m != nil {
		varName := m[1]
		if _, ok := knownVars[varName]; ok {
			if !alreadyCaptured(accesses, varName) {
				accesses = append(accesses, StateAccess{
					VarName: varName, FullExpr: trimmed,
					Line: trimmed, LineNum: lineNum,
				})
			}
		}
	}

	// Increment/decrement: nonces[owner]++
	if m := p.incDecRe.FindStringSubmatch(line); m != nil {
		varName := m[1]
		if _, ok := knownVars[varName]; ok {
			if !alreadyCaptured(accesses, varName) {
				accesses = append(accesses, StateAccess{
					VarName: varName, FullExpr: trimmed,
					Line: trimmed, LineNum: lineNum,
				})
			}
		}
	}

	return accesses
}

func (p *lineParser) extractReads(
	line string,
	lineNum int,
	knownVars map[string]StateVar,
) []StateAccess {

	var accesses []StateAccess
	trimmed := strings.TrimSpace(line)

	// Skip write lines. They are already handled.
	if p.mappingWriteRe.MatchString(line) ||
		p.simpleWriteRe.MatchString(line) ||
		p.compoundWriteRe.MatchString(line) {
		// May still have reads on the right-hand side, but
		// tracking those adds complexity without major detector value.
		return nil
	}

	// Mapping access in require / if conditions
	if m := p.mappingAccessRe.FindAllStringSubmatch(line, -1); m != nil {
		for _, match := range m {
			varName := match[1]
			if _, ok := knownVars[varName]; ok {
				if !alreadyCaptured(accesses, varName) {
					accesses = append(accesses, StateAccess{
						VarName:   varName,
						FullExpr:  match[0],
						Line:      trimmed,
						LineNum:   lineNum,
						IsMapping: true,
						MapKey:    strings.TrimSpace(match[2]),
					})
				}
			}
		}
	}

	return accesses
}

func alreadyCaptured(accesses []StateAccess, varName string) bool {
	for _, a := range accesses {
		if a.VarName == varName {
			return true
		}
	}
	return false
}

// extractCalleeMethod attempts to extract the callee object and method name
// from a call expression like "msg.sender.call{value:x}(...)".
func extractCalleeMethod(line, method string) (callee, _ string) {
	// Simple heuristic: find the pattern "X.method("
	re := regexp.MustCompile(`(\w[\w.]*)\s*\.\s*` + regexp.QuoteMeta(method))
	if m := re.FindStringSubmatch(line); m != nil {
		return m[1], method
	}
	return "unknown", method
}
