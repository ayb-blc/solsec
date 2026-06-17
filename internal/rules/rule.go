package rules

// RuleID is a stable identifier in the format SOLSEC-<CATEGORY>-<NUMBER>.
type RuleID string

func (r RuleID) String() string { return string(r) }

// Category groups rules by vulnerability family.
type Category string

const (
	CategoryReentrancy     Category = "REENTRANCY"
	CategoryAuthentication Category = "AUTH"
	CategoryAccessControl  Category = "ACCESS"
	CategoryArithmetic     Category = "ARITHMETIC"
	CategoryCallSafety     Category = "CALL"
	CategoryUpgrade        Category = "UPGRADE"
	CategoryOnChain        Category = "ONCHAIN"
	CategoryInterContract  Category = "INTERCONTRACT"
	CategoryShadowing      Category = "SHADOW"
	CategoryDeFi           Category = "DEFI"
	CategoryGas            Category = "GAS"
)

type Severity string

const (
	SeverityCritical      Severity = "critical"
	SeverityHigh          Severity = "high"
	SeverityMedium        Severity = "medium"
	SeverityLow           Severity = "low"
	SeverityInformational Severity = "informational"
)

type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

type Language string

const (
	LanguageSolidity Language = "solidity"
	LanguageVyper    Language = "vyper"
	LanguageBoth     Language = "both"
)

type Rule struct {
	// ID is the unique rule identifier.
	ID RuleID `json:"id" yaml:"id"`

	Name string `json:"name" yaml:"name"`

	ShortDescription string `json:"short_description" yaml:"short_description"`

	FullDescription string `json:"full_description" yaml:"full_description"`

	Severity Severity `json:"severity" yaml:"severity"`

	Confidence Confidence `json:"confidence" yaml:"confidence"`

	// Category groups the rule by vulnerability family.
	Category Category `json:"category" yaml:"category"`

	// Language desteklenen dil
	Language Language `json:"language" yaml:"language"`

	Tags []string `json:"tags" yaml:"tags"`

	Remediation string `json:"remediation" yaml:"remediation"`

	References RuleReferences `json:"references" yaml:"references"`

	Examples RuleExamples `json:"examples" yaml:"examples"`

	// Enabled controls whether this rule is active.
	Enabled bool `json:"enabled" yaml:"enabled"`

	DetectorName string `json:"detector_name" yaml:"detector_name"`
}

// RuleReferences contains related standards and external references.
type RuleReferences struct {
	// SWC Smart Contract Weakness Classification
	// https://swcregistry.io/
	SWC []string `json:"swc,omitempty" yaml:"swc,omitempty"`

	// CWE Common Weakness Enumeration
	// https://cwe.mitre.org/
	CWE []string `json:"cwe,omitempty" yaml:"cwe,omitempty"`

	// URLs contains additional reference links.
	URLs []string `json:"urls,omitempty" yaml:"urls,omitempty"`

	// EIP contains related Ethereum Improvement Proposals.
	EIP []string `json:"eip,omitempty" yaml:"eip,omitempty"`
}

type RuleExamples struct {
	Vulnerable string `json:"vulnerable,omitempty" yaml:"vulnerable,omitempty"`

	Safe string `json:"safe,omitempty" yaml:"safe,omitempty"`
}

func (r *Rule) CVSSScore() float64 {
	switch r.Severity {
	case SeverityCritical:
		return 9.8
	case SeverityHigh:
		return 7.5
	case SeverityMedium:
		return 5.0
	case SeverityLow:
		return 2.5
	default:
		return 0.0
	}
}

func (r *Rule) SARIFLevel() string {
	switch r.Severity {
	case SeverityCritical, SeverityHigh:
		return "error"
	case SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

func (r *Rule) SARIFPrecision() string {
	switch r.Confidence {
	case ConfidenceHigh:
		return "high"
	case ConfidenceMedium:
		return "medium"
	default:
		return "low"
	}
}
