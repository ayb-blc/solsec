// internal/pathtracker/types.go

package pathtracker

// GuardKind classifies the security role of an early guard.
type GuardKind uint8

const (
	GuardAccessControl GuardKind = iota // msg.sender equality or mapping check
	GuardReentrancy                     // reentrancy lock (require(!locked))
	GuardPaused                         // pause state check
	GuardInitialized                    // initialization flag
	GuardOther                          // generic require/if+revert
)

func (k GuardKind) String() string {
	switch k {
	case GuardAccessControl:
		return "access-control"
	case GuardReentrancy:
		return "reentrancy"
	case GuardPaused:
		return "paused"
	case GuardInitialized:
		return "initialized"
	default:
		return "other"
	}
}

// EarlyGuard is a pre-condition found near the start of a function that
// gates whether the rest of the body executes.
//
// Examples:
//
//	require(msg.sender == owner)    → GuardAccessControl
//	if (!authorized) revert()       → GuardAccessControl
//	require(!_locked)               → GuardReentrancy
//	require(!initialized)           → GuardInitialized
type EarlyGuard struct {
	Kind      GuardKind
	Condition string // the condition expression
	Line      string // raw source line
	LineNum   int
}

// IsAccessControl reports whether this guard restricts who can call.
func (g EarlyGuard) IsAccessControl() bool {
	return g.Kind == GuardAccessControl
}

// IsReentrancyGuard reports whether this guard prevents reentrancy.
func (g EarlyGuard) IsReentrancyGuard() bool {
	return g.Kind == GuardReentrancy
}

// MutexPattern describes a custom reentrancy mutex implemented without
// using a standard modifier (nonReentrant, lock, etc.).
//
// Pattern:
//
//	require(!_locked);  ← CheckLine
//	_locked = true;     ← SetLine
//	...
//	_locked = false;    ← ResetLine
type MutexPattern struct {
	LockVar   string // name of the mutex variable (e.g., "_locked")
	CheckLine int    // line of the require(!var) / if (var) revert
	SetLine   int    // line of var = true
	ResetLine int    // line of var = false
}

// ConditionalWrite describes a state write that occurs inside a
// conditional block. The condition may restrict which callers can
// reach the write.
type ConditionalWrite struct {
	VarName            string // state variable being written
	Condition          string // the if condition expression
	IsAccessControlled bool   // condition involves msg.sender check
	IfLineNum          int    // line of the enclosing if statement
	WriteLineNum       int    // line of the actual write
}

// BranchContext holds the conditions enclosing a specific line.
// Used to understand what must be true when a line executes.
type BranchContext struct {
	// Conditions is the stack of if/else conditions enclosing the line,
	// from outermost to innermost.
	Conditions []ConditionFrame

	// Depth is the brace nesting depth at the given line.
	Depth int
}

// ConditionFrame is one level of if/else nesting.
type ConditionFrame struct {
	Condition string // raw condition string
	IsNegated bool   // inside an else branch
	LineNum   int
}

// HasMsgSenderCheck reports whether any condition in the context
// restricts who can reach this code.
func (bc *BranchContext) HasMsgSenderCheck() bool {
	for _, c := range bc.Conditions {
		if isMsgSenderCondition(c.Condition) {
			return true
		}
	}
	return false
}
