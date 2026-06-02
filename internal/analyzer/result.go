package analyzer

// internal/analyzer/result.go

// Severity describes the impact level assigned to a finding.
type Severity int

const (
	Info Severity = iota
	Low
	Medium
	High
	Critical
)

func (s Severity) String() string {
	switch s {
	case Info:
		return "INFO"
	case Low:
		return "LOW"
	case Medium:
		return "MEDIUM"
	case High:
		return "HIGH"
	case Critical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// Color returns the ANSI color escape code associated with the severity.
func (s Severity) Color() string {
	switch s {
	case Info:
		return "\033[36m" // Cyan
	case Low:
		return "\033[33m" // Yellow
	case Medium:
		return "\033[33m" // Yellow
	case High:
		return "\033[31m" // Red
	case Critical:
		return "\033[35m" // Magenta
	default:
		return "\033[0m"
	}
}

type Confidence int

const (
	ConfidenceLow Confidence = iota
	ConfidenceMedium
	ConfidenceHigh
)

func (c Confidence) String() string {
	switch c {
	case ConfidenceLow:
		return "LOW"
	case ConfidenceMedium:
		return "MEDIUM"
	case ConfidenceHigh:
		return "HIGH"
	default:
		return "UNKNOWN"
	}
}
