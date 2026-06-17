// internal/pathtracker/pathtracker.go

package pathtracker

// PathTracker performs lightweight, localized control flow analysis on
// function bodies. It does NOT build a full CFG — instead it answers
// specific safety questions through pattern matching with context awareness.
//
// Supported queries:
//
//  1. FindEarlyGuards   — what pre-conditions gate the function body?
//  2. FindCustomMutex   — is there a manual reentrancy lock?
//  3. GetBranchContext  — what conditions enclose a specific line?
//
// Limitations (by design):
//   - No cross-function dataflow
//   - No loop analysis
//   - Condition tracking is syntactic, not semantic
//   - Works best on typical DeFi contract patterns
type PathTracker struct {
	// How many lines from function start to scan for early guards.
	guardScanDepth int

	guards *guardScanner
	mutex  *mutexScanner
	branch *branchScanner
}

// New creates a PathTracker with default settings.
func New() *PathTracker {
	return &PathTracker{
		guardScanDepth: 20,
		guards:         newGuardScanner(),
		mutex:          newMutexScanner(),
		branch:         newBranchScanner(),
	}
}

// FindEarlyGuards scans the first guardScanDepth body lines for
// require/if+revert patterns that gate execution of the rest of the body.
//
// An "early" guard is one that appears before any state writes or external
// calls — it acts as a precondition for the rest of the function.
func (t *PathTracker) FindEarlyGuards(bodyLines []string) []EarlyGuard {
	return t.guards.scan(bodyLines, t.guardScanDepth)
}

// HasAccessControlGuard is a convenience wrapper that returns true if
// any early guard restricts execution based on msg.sender.
func (t *PathTracker) HasAccessControlGuard(bodyLines []string) bool {
	for _, g := range t.FindEarlyGuards(bodyLines) {
		if g.IsAccessControl() {
			return true
		}
	}
	return false
}

// HasReentrancyGuard returns true if the function body contains either
// an early reentrancy guard (require(!locked)) or a full mutex pattern.
func (t *PathTracker) HasReentrancyGuard(bodyLines []string, contractSrc string) bool {
	for _, g := range t.FindEarlyGuards(bodyLines) {
		if g.IsReentrancyGuard() {
			return true
		}
	}
	return t.FindCustomMutex(bodyLines, contractSrc) != nil
}

// FindCustomMutex looks for a manual reentrancy mutex pattern:
//
//	require(!_locked) or require(_status == NOT_ENTERED)
//	_locked = true
//	... (external calls or other logic)
//	_locked = false
//
// contractSrc is the full contract source (needed to confirm the
// mutex variable is a state variable, not a local).
func (t *PathTracker) FindCustomMutex(bodyLines []string, contractSrc string) *MutexPattern {
	return t.mutex.find(bodyLines, contractSrc)
}

// GetBranchContext returns the conditions enclosing the line at lineOffset
// within bodyLines. lineOffset is 0-indexed from the start of bodyLines.
//
// Used to answer: "Is this state write inside an access-controlled if block?"
func (t *PathTracker) GetBranchContext(bodyLines []string, lineOffset int) *BranchContext {
	return t.branch.contextAt(bodyLines, lineOffset)
}

// IsConditionalWrite checks whether a state write at lineOffset is inside
// a conditional block that restricts access (e.g., if(msg.sender==owner)).
func (t *PathTracker) IsConditionalWrite(
	bodyLines []string,
	lineOffset int,
	varName string,
) *ConditionalWrite {

	ctx := t.GetBranchContext(bodyLines, lineOffset)
	if ctx == nil || len(ctx.Conditions) == 0 {
		return nil
	}

	for _, frame := range ctx.Conditions {
		if isMsgSenderCondition(frame.Condition) {
			return &ConditionalWrite{
				VarName:            varName,
				Condition:          frame.Condition,
				IsAccessControlled: true,
				IfLineNum:          frame.LineNum,
				WriteLineNum:       lineOffset,
			}
		}
	}

	// Inside an if block, but not access-controlled
	top := ctx.Conditions[len(ctx.Conditions)-1]
	return &ConditionalWrite{
		VarName:            varName,
		Condition:          top.Condition,
		IsAccessControlled: false,
		IfLineNum:          top.LineNum,
		WriteLineNum:       lineOffset,
	}
}
