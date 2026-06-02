package detectors

import (
	"fmt"
	"strings"

	"github.com/ayb-blc/solsec/internal/analyzer"
	"github.com/ayb-blc/solsec/internal/parser"
)

type UnifiedDetector interface {
	Name() string
	Description() string
	Severity() analyzer.Severity
	SupportedLanguages() []parser.Language
	AnalyzeUnified(ast *parser.UnifiedAST) ([]analyzer.Finding, error)
}

type UnifiedReentrancyDetector struct{}

func NewUnifiedReentrancyDetector() *UnifiedReentrancyDetector {
	return &UnifiedReentrancyDetector{}
}

func (d *UnifiedReentrancyDetector) Name() string                { return "reentrancy" }
func (d *UnifiedReentrancyDetector) Severity() analyzer.Severity { return analyzer.Critical }
func (d *UnifiedReentrancyDetector) Description() string {
	return "Detects reentrancy vulnerabilities across normalized Solidity and Vyper ASTs"
}
func (d *UnifiedReentrancyDetector) SupportedLanguages() []parser.Language {
	return []parser.Language{parser.LanguageSolidity, parser.LanguageVyper}
}

func (d *UnifiedReentrancyDetector) AnalyzeUnified(ast *parser.UnifiedAST) ([]analyzer.Finding, error) {
	var findings []analyzer.Finding
	if ast == nil {
		return findings, nil
	}
	for _, contract := range ast.Contracts {
		for _, fn := range contract.Functions {
			if f := d.analyzeFunction(fn, contract, ast); f != nil {
				findings = append(findings, *f)
			}
		}
	}
	return findings, nil
}

func (d *UnifiedReentrancyDetector) analyzeFunction(
	fn *parser.UnifiedFunction,
	contract *parser.UnifiedContract,
	ast *parser.UnifiedAST,
) *analyzer.Finding {
	if fn == nil || contract == nil {
		return nil
	}
	if fn.Mutability == "view" || fn.Mutability == "pure" {
		return nil
	}
	for _, mod := range fn.Modifiers {
		if mod == "nonreentrant" || mod == "nonReentrant" {
			return nil
		}
	}

	externalCallIdx := -1
	for i, stmt := range fn.Body {
		if stmt == nil {
			continue
		}
		if stmt.ContainsExternalCall && externalCallIdx < 0 {
			externalCallIdx = i
			continue
		}
		if externalCallIdx >= 0 && stmt.WritesState {
			return &analyzer.Finding{
				DetectorName: d.Name(),
				Title:        fmt.Sprintf("Reentrancy in %s.%s", contract.Name, fn.Name),
				Description: fmt.Sprintf(
					"Function %q makes an external call before updating state. This violates the Checks-Effects-Interactions pattern.",
					fn.Name,
				),
				Recommendation: reentrancyRecommendation(ast.Language),
				Filepath:       ast.Filepath,
				Line:           fn.Line,
				Severity:       analyzer.Critical,
				Confidence:     analyzer.ConfidenceHigh,
				Tags:           []string{"reentrancy", "cei-violation", string(ast.Language)},
			}
		}
	}
	return nil
}

func reentrancyRecommendation(lang parser.Language) string {
	if lang == parser.LanguageVyper {
		return "Update state before raw_call/send and add @nonreentrant where appropriate."
	}
	return "Update state before external calls and use ReentrancyGuard's nonReentrant modifier where appropriate."
}

type UnifiedTxOriginDetector struct{}

func NewUnifiedTxOriginDetector() *UnifiedTxOriginDetector {
	return &UnifiedTxOriginDetector{}
}

func (d *UnifiedTxOriginDetector) Name() string                { return "tx-origin" }
func (d *UnifiedTxOriginDetector) Severity() analyzer.Severity { return analyzer.High }
func (d *UnifiedTxOriginDetector) Description() string {
	return "Detects tx.origin misuse across normalized Solidity and Vyper sources"
}
func (d *UnifiedTxOriginDetector) SupportedLanguages() []parser.Language {
	return []parser.Language{parser.LanguageSolidity, parser.LanguageVyper}
}

func (d *UnifiedTxOriginDetector) AnalyzeUnified(ast *parser.UnifiedAST) ([]analyzer.Finding, error) {
	var findings []analyzer.Finding
	if ast == nil {
		return findings, nil
	}
	for i, line := range ast.Lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") ||
			strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "*") {
			continue
		}
		if !strings.Contains(line, "tx.origin") {
			continue
		}
		if strings.Contains(line, "tx.origin == msg.sender") ||
			strings.Contains(line, "msg.sender == tx.origin") {
			continue
		}
		if strings.Contains(line, "require") || strings.Contains(line, "assert") ||
			strings.Contains(line, "if ") {
			findings = append(findings, analyzer.Finding{
				DetectorName:   d.Name(),
				Title:          "tx.origin used for authentication",
				Description:    "tx.origin is used for access control. This can be exploited via phishing because an attacker's contract can call this contract while tx.origin remains the victim.",
				Recommendation: "Replace tx.origin with msg.sender for authentication.",
				Filepath:       ast.Filepath,
				Line:           i + 1,
				CodeSnippet:    trimmed,
				Severity:       analyzer.High,
				Confidence:     analyzer.ConfidenceHigh,
				Tags:           []string{"tx-origin", "authentication", string(ast.Language)},
			})
		}
	}
	return findings, nil
}
