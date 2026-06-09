// internal/inheritancegraph/modifier.go

package inheritancegraph

import "strings"

// ModifierCategory is the broad security role a modifier plays.
type ModifierCategory uint8

const (
	// CategoryUnknown means the modifier body could not be classified.
	CategoryUnknown ModifierCategory = iota

	// CategoryAccessControl checks who can call the function.
	// Typical patterns: require(msg.sender == owner), hasRole(ROLE, msg.sender)
	CategoryAccessControl

	// CategoryReentrancyGuard prevents reentrant calls.
	// Typical patterns: bool locked flag, uint256 status check (OZ)
	CategoryReentrancyGuard

	// CategoryPauseCheck requires a specific pause state.
	// Typical: require(!paused()), require(paused())
	CategoryPauseCheck

	// CategoryInitializerOnce allows execution only once.
	// Typical: require(!_initialized), initializer modifier
	CategoryInitializerOnce

	// CategoryTimeLock is a time-based constraint.
	// Typical: require(block.timestamp >= releaseTime)
	CategoryTimeLock

	// CategoryOther means the modifier is recognized but does not fit above.
	CategoryOther
)

func (c ModifierCategory) String() string {
	switch c {
	case CategoryAccessControl:
		return "access-control"
	case CategoryReentrancyGuard:
		return "reentrancy-guard"
	case CategoryPauseCheck:
		return "pause-check"
	case CategoryInitializerOnce:
		return "initializer-once"
	case CategoryTimeLock:
		return "timelock"
	case CategoryOther:
		return "other"
	default:
		return "unknown"
	}
}

// ModifierDef is the fully resolved definition of a Solidity modifier,
// including its body analysis and security classification.
type ModifierDef struct {
	// Name is the modifier identifier.
	Name string

	// Contract is the contract that declares this modifier.
	// If the modifier is inherited, this points to the ancestor.
	Contract *ContractNode

	Params string

	BodyLines []string

	Category ModifierCategory

	Checks []ModifierCheck

	// IsWellKnown is true for modifiers from standard libraries
	// (OZ nonReentrant, onlyOwner, whenNotPaused, etc.) that are
	// classified from their name rather than body analysis.
	IsWellKnown bool
}

func (m *ModifierDef) IsAccessControl() bool {
	return m.Category == CategoryAccessControl
}

func (m *ModifierDef) IsReentrancyGuard() bool {
	return m.Category == CategoryReentrancyGuard
}

func (m *ModifierDef) IsPauseCheck() bool {
	return m.Category == CategoryPauseCheck
}

type ModifierCheck struct {
	Kind    CheckKind
	Pattern string
}

// CheckKind is the specific type of check a modifier performs.
type CheckKind uint8

const (
	CheckUnknown CheckKind = iota

	CheckMsgSenderEquals

	CheckMsgSenderNotEquals

	CheckMsgSenderHasRole

	CheckMsgSenderMapping

	CheckReentrancyFlag

	CheckReentrancyMutation

	CheckPauseState

	CheckInitializedFlag

	CheckTimestamp
)

func (k CheckKind) String() string {
	switch k {
	case CheckMsgSenderEquals:
		return "msg.sender=="
	case CheckMsgSenderNotEquals:
		return "msg.sender!="
	case CheckMsgSenderHasRole:
		return "hasRole(msg.sender)"
	case CheckMsgSenderMapping:
		return "mapping[msg.sender]"
	case CheckReentrancyFlag:
		return "reentrancy-check"
	case CheckReentrancyMutation:
		return "reentrancy-lock"
	case CheckPauseState:
		return "pause-state"
	case CheckInitializedFlag:
		return "initialized-flag"
	case CheckTimestamp:
		return "timestamp-check"
	default:
		return "unknown"
	}
}

// wellKnownModifiers maps standard library modifier names to their
// ModifierCategory. Used when the modifier body is not available
// (e.g., defined in an unresolved import).
var wellKnownModifiers = map[string]ModifierCategory{
	// OZ Ownable / OwnableUpgradeable
	"onlyOwner": CategoryAccessControl,

	// OZ AccessControl / AccessControlUpgradeable
	"onlyRole": CategoryAccessControl,

	// OZ ReentrancyGuard / ReentrancyGuardUpgradeable
	"nonReentrant": CategoryReentrancyGuard,
	"nonreentrant": CategoryReentrancyGuard,

	// OZ Pausable / PausableUpgradeable
	"whenNotPaused": CategoryPauseCheck,
	"whenPaused":    CategoryPauseCheck,

	// OZ Initializable
	"initializer":      CategoryInitializerOnce,
	"reinitializer":    CategoryInitializerOnce,
	"onlyInitializing": CategoryInitializerOnce,

	// Common DeFi patterns
	"lock":                         CategoryReentrancyGuard, // Uniswap V2
	"noDelegateCall":               CategoryOther,           // Uniswap V3
	"onlyBridge":                   CategoryAccessControl,
	"onlyPool":                     CategoryAccessControl,
	"onlyPoolAdmin":                CategoryAccessControl,
	"onlyEmergencyAdmin":           CategoryAccessControl,
	"onlyEmergencyOrPoolAdmin":     CategoryAccessControl,
	"onlyAssetListingOrPoolAdmins": CategoryAccessControl,
	"onlyRiskOrPoolAdmins":         CategoryAccessControl,
	"onlyPoolConfigurator":         CategoryAccessControl,
	"ifAdmin":                      CategoryAccessControl,
	"onlyProxyAdmin":               CategoryAccessControl,
	"adminOnly":                    CategoryAccessControl,
	"requiresAuth":                 CategoryAccessControl,
	"restricted":                   CategoryAccessControl,
	"protected":                    CategoryAccessControl,
	"auth":                         CategoryAccessControl,
}

// ClassifyByName returns the category for a well-known modifier name,
// or CategoryUnknown if the name is not recognized.
func ClassifyByName(name string) (ModifierCategory, bool) {
	if cat, ok := wellKnownModifiers[name]; ok {
		return cat, true
	}
	// Pattern matching for common prefixes
	lower := strings.ToLower(name)
	switch {
	case strings.HasPrefix(lower, "onlyrole"):
		return CategoryAccessControl, true
	case strings.HasPrefix(lower, "only") && len(lower) > 4:
		return CategoryAccessControl, true
	case strings.HasPrefix(lower, "nonreentrant"):
		return CategoryReentrancyGuard, true
	case strings.HasPrefix(lower, "whennotpaused"), strings.HasPrefix(lower, "whenpaused"):
		return CategoryPauseCheck, true
	}
	return CategoryUnknown, false
}
