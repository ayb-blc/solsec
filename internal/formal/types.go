package formal

import (
	"time"

	"github.com/ayb-blc/solsec/internal/analyzer"
)

type Tool string

const (
	ToolManticore Tool = "manticore"
	ToolEchidna   Tool = "echidna"
	ToolMythril   Tool = "mythril"
	ToolSlither   Tool = "slither"
)

func (t Tool) String() string { return string(t) }

type ToolAvailability struct {
	Tool      Tool
	Available bool
	Version   string
	Path      string
	Error     string
}

type FuzzTarget struct {
	ContractPath string

	ContractName string

	FunctionName string

	SourceFinding *analyzer.Finding

	Priority FuzzPriority

	Properties []FuzzProperty

	SeedValues []SeedValue
}

type FuzzPriority int

const (
	PriorityLow      FuzzPriority = 1
	PriorityMedium   FuzzPriority = 2
	PriorityHigh     FuzzPriority = 3
	PriorityCritical FuzzPriority = 4
)

func (p FuzzPriority) String() string {
	switch p {
	case PriorityCritical:
		return "critical"
	case PriorityHigh:
		return "high"
	case PriorityMedium:
		return "medium"
	default:
		return "low"
	}
}

type FuzzProperty struct {
	Name string

	Description string

	SolidityCode string

	PythonCode string

	Kind PropertyKind
}

type PropertyKind string

const (
	PropertyReentrancy       PropertyKind = "reentrancy"
	PropertyAccessControl    PropertyKind = "access_control"
	PropertyArithmetic       PropertyKind = "arithmetic"
	PropertyETHBalance       PropertyKind = "eth_balance"
	PropertyStateConsistency PropertyKind = "state_consistency"
	PropertyCustom           PropertyKind = "custom"
)

type SeedValue struct {
	ParamName string

	Value string

	Reason string
}

type VerificationResult struct {
	Tool       Tool
	Target     *FuzzTarget
	Status     VerificationStatus
	Duration   time.Duration
	Violations []Violation
	Coverage   *CoverageInfo
	Error      string
	RawOutput  string
}

type VerificationStatus string

const (
	StatusSafe      VerificationStatus = "safe"
	StatusViolation VerificationStatus = "violation"
	StatusTimeout   VerificationStatus = "timeout"
	StatusError     VerificationStatus = "error"
	StatusUnknown   VerificationStatus = "unknown"
)

type Violation struct {
	// PropertyName ihlal edilen invariant
	PropertyName string

	Description string

	CounterExample *CounterExample

	// Severity ihlal ciddiyeti
	Severity analyzer.Severity
}

// CounterExample ihlali tetikleyen input.
type CounterExample struct {
	Calls []ContractCall

	InitialState map[string]string

	FinalState map[string]string
}

type ContractCall struct {
	Function string
	Args     []string
	Caller   string
	Value    string
}

// CoverageInfo coverage bilgisi.
type CoverageInfo struct {
	LinesCovered    int
	LinesTotal      int
	BranchesCovered int
	BranchesTotal   int
}

func (c *CoverageInfo) LinePercent() float64 {
	if c.LinesTotal == 0 {
		return 0
	}
	return float64(c.LinesCovered) / float64(c.LinesTotal) * 100
}
