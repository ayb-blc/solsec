package detectors

import (
	"fmt"

	"github.com/ayb-blc/solsec/internal/analyzer"
	"github.com/ayb-blc/solsec/internal/symboltable"
)

// ShadowingDetector detects local variables or parameters that shadow state variables.
type ShadowingDetector struct{}

func NewShadowingDetector() *ShadowingDetector {
	return &ShadowingDetector{}
}

func (d *ShadowingDetector) Name() string                { return "variable-shadowing" }
func (d *ShadowingDetector) Severity() analyzer.Severity { return analyzer.Medium }
func (d *ShadowingDetector) Description() string {
	return "Detects local variables or parameters that shadow state variables"
}

func (d *ShadowingDetector) AnalyzeWithSymbolTable(
	table *symboltable.SymbolTable,
	filepath string,
) ([]analyzer.Finding, error) {

	var findings []analyzer.Finding

	for _, sym := range table.AllSymbols {
		if sym.Kind != symboltable.KindLocalVariable &&
			sym.Kind != symboltable.KindParameter &&
			sym.Kind != symboltable.KindReturnVariable {
			continue
		}

		declaredScope := sym.DeclaredInScope
		if declaredScope == nil {
			continue
		}

		contractScope := declaredScope.ContractScope()
		if contractScope == nil {
			continue
		}

		shadowedSym, _ := contractScope.Lookup(sym.Name)
		if shadowedSym == nil || !shadowedSym.IsStateVariable() {
			continue
		}

		lineNumber := 0
		if table.SourceMap != nil && sym.DeclarationNode != nil {
			lineNumber = table.SourceMap.LineOf(sym.DeclarationNode.Src)
		}

		findings = append(findings, analyzer.Finding{
			DetectorName: d.Name(),
			Title: fmt.Sprintf(
				"%s '%s' shadows state variable in '%s'",
				sym.Kind, sym.Name, contractScope.Name,
			),
			Description: fmt.Sprintf(
				"The %s '%s' declared in function '%s' shadows the state variable '%s' "+
					"declared at contract level. Any assignment to '%s' within this function "+
					"modifies the local copy, NOT the contract state.",
				sym.Kind, sym.Name,
				declaredScope.FunctionScope().Name,
				sym.Name,
				sym.Name,
			),
			Recommendation: fmt.Sprintf(
				"Rename the %s to avoid shadowing. "+
					"For example: '%sLocal' or '%sParam'. "+
					"This makes the code's intent unambiguous.",
				sym.Kind, sym.Name, sym.Name,
			),
			Filepath:   filepath,
			Line:       lineNumber,
			Severity:   analyzer.Medium,
			Confidence: analyzer.ConfidenceHigh,
			Tags:       []string{"shadowing", "state-variable", "logic-bug"},
		})
	}

	return findings, nil
}
