package reporter

import (
	"github.com/ayb-blc/solsec/internal/analyzer"
	"github.com/ayb-blc/solsec/internal/rules"
)

func enrichFinding(f *analyzer.Finding) {
	if f.Rule != nil {
		return // Zaten dolu
	}
	if f.RuleID == "" {
		return
	}
	rule, ok := rules.Lookup(f.RuleID)
	if !ok {
		return
	}
	f.Rule = rule
}

func effectiveRuleID(f analyzer.Finding) string {
	if f.RuleID != "" {
		return string(f.RuleID)
	}
	return f.DetectorName
}
