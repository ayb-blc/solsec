package detectors

import (
	"github.com/ayb-blc/solsec/internal/analyzer"
	"github.com/ayb-blc/solsec/internal/rules"
)

func detectorFinding(ruleID rules.RuleID, filepath string, line int, snippet string) analyzer.Finding {
	rule := rules.Global().MustGet(ruleID)
	return analyzer.Finding{
		RuleID:         rule.ID,
		Rule:           rule,
		DetectorName:   rule.DetectorName,
		Title:          rule.Name,
		Description:    rule.FullDescription,
		Recommendation: rule.Remediation,
		Filepath:       filepath,
		Line:           line,
		CodeSnippet:    snippet,
		Severity:       analyzerSeverity(rule.Severity),
		Confidence:     analyzerConfidence(rule.Confidence),
		Tags:           append([]string(nil), rule.Tags...),
	}
}

func analyzerSeverity(severity rules.Severity) analyzer.Severity {
	switch severity {
	case rules.SeverityCritical:
		return analyzer.Critical
	case rules.SeverityHigh:
		return analyzer.High
	case rules.SeverityMedium:
		return analyzer.Medium
	case rules.SeverityLow:
		return analyzer.Low
	default:
		return analyzer.Info
	}
}

func analyzerConfidence(confidence rules.Confidence) analyzer.Confidence {
	switch confidence {
	case rules.ConfidenceHigh:
		return analyzer.ConfidenceHigh
	case rules.ConfidenceLow:
		return analyzer.ConfidenceLow
	default:
		return analyzer.ConfidenceMedium
	}
}
