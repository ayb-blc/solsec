package suppression

import (
	"regexp"

	"github.com/ayb-blc/solsec/internal/analyzer"
	"github.com/ayb-blc/solsec/internal/config"
	"github.com/ayb-blc/solsec/internal/rules"
)

// 1. Inline direktifler (// solsec-disable-next-line)
type Engine struct {
	configSuppression *ConfigSuppression
	inlineCache       map[string]*FileSuppressions
	parser            *InlineSuppressionParser
	configWarnings    []string
}

func NewEngine(cfg *config.Config) *Engine {
	cs, warnings := NewConfigSuppression(cfg)
	return &Engine{
		configSuppression: cs,
		inlineCache:       make(map[string]*FileSuppressions),
		parser:            NewInlineSuppressionParser(),
		configWarnings:    warnings,
	}
}

func (e *Engine) ConfigWarnings() []string {
	return e.configWarnings
}

func (e *Engine) RegisterFile(filepath, source string) {
	e.inlineCache[filepath] = e.parser.Parse(source)
}

func (e *Engine) IsSuppressed(f analyzer.Finding) bool {
	ruleID := f.RuleID
	if ruleID == "" {
		ruleID = rules.RuleID(f.DetectorName)
	}

	// 1. Inline suppression
	if fs, ok := e.inlineCache[f.Filepath]; ok {
		if fs.IsSuppressed(ruleID, f.Line) {
			return true
		}
	}

	// 2. Config suppression
	funcName := extractFunctionName(f)
	return e.configSuppression.IsSuppressed(ruleID, f.Filepath, funcName)
}

func (e *Engine) FilterResults(results []analyzer.AnalysisResult) ([]analyzer.AnalysisResult, int) {
	total := 0
	filtered := make([]analyzer.AnalysisResult, len(results))

	for i, result := range results {
		var kept []analyzer.Finding
		for _, f := range result.Findings {
			if e.IsSuppressed(f) {
				total++
				continue
			}
			kept = append(kept, f)
		}
		filtered[i] = analyzer.AnalysisResult{
			Filepath: result.Filepath,
			Findings: kept,
			Error:    result.Error,
		}
	}

	return filtered, total
}

func (e *Engine) SuppressedCount(results []analyzer.AnalysisResult) int {
	count := 0
	for _, result := range results {
		for _, f := range result.Findings {
			if e.IsSuppressed(f) {
				count++
			}
		}
	}
	return count
}

func extractFunctionName(f analyzer.Finding) string {
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`in (?:function )?'(\w+)'`),
		regexp.MustCompile(`in (?:function )?"(\w+)"`),
	}

	for _, p := range patterns {
		if m := p.FindStringSubmatch(f.Title); len(m) > 1 {
			return m[1]
		}
	}
	for _, p := range patterns {
		if m := p.FindStringSubmatch(f.Description); len(m) > 1 {
			return m[1]
		}
	}
	return ""
}
