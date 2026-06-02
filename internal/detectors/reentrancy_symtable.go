package detectors

import (
	"fmt"

	"github.com/ayb-blc/solsec/internal/analyzer"
	"github.com/ayb-blc/solsec/internal/parser"
	"github.com/ayb-blc/solsec/internal/symboltable"
)

// ReentrancySymbolTableDetector uses symbol data to identify CEI violations.
type ReentrancySymbolTableDetector struct{}

func NewReentrancySymbolTableDetector() *ReentrancySymbolTableDetector {
	return &ReentrancySymbolTableDetector{}
}

func (d *ReentrancySymbolTableDetector) Name() string                { return "reentrancy-symtable" }
func (d *ReentrancySymbolTableDetector) Severity() analyzer.Severity { return analyzer.Critical }
func (d *ReentrancySymbolTableDetector) Description() string {
	return "Symbol table-based reentrancy: tracks exact state variable writes after external calls"
}

func (d *ReentrancySymbolTableDetector) AnalyzeWithSymbolTable(
	table *symboltable.SymbolTable,
	unit *parser.SourceUnit,
	filepath string,
) ([]analyzer.Finding, error) {

	var findings []analyzer.Finding

	for _, sym := range table.AllSymbols {

		if !sym.IsStateVariable() {
			continue
		}

		if !sym.WrittenAfterExternalCall {
			continue
		}

		problematicFunctions := d.findProblematicFunctions(sym, table)

		for _, fnInfo := range problematicFunctions {

			if fnInfo.hasNonReentrant {
				continue
			}

			if fnInfo.contractHasGuard {
				continue
			}

			lineNumber := 0
			if table.SourceMap != nil && sym.DeclarationNode != nil {
				lineNumber = table.SourceMap.LineOf(sym.DeclarationNode.Src)
			}

			findings = append(findings, analyzer.Finding{
				DetectorName: d.Name(),
				Title: fmt.Sprintf(
					"State variable '%s' written after external call in '%s.%s'",
					sym.Name, fnInfo.contractName, fnInfo.functionName,
				),
				Description: fmt.Sprintf(
					"State variable '%s' (declared as %s, type: %s) is written %d time(s) "+
						"after an external call in function '%s.%s'. "+
						"This violates the Checks-Effects-Interactions pattern.\n\n"+
						"If an attacker's contract is called (via ETH transfer or .call()), "+
						"it can re-enter '%s' before '%s' is updated, "+
						"potentially exploiting the inconsistent state.",
					sym.Name,
					sym.Kind,
					sym.TypeName,
					fnInfo.writeAfterCallCount,
					fnInfo.contractName, fnInfo.functionName,
					fnInfo.functionName,
					sym.Name,
				),
				Recommendation: fmt.Sprintf(
					"Option 1 (CEI): Update '%s' BEFORE the external call.\n"+
						"Option 2 (Guard): Add 'nonReentrant' modifier from OpenZeppelin's ReentrancyGuard.\n\n"+
						"CEI fix:\n"+
						"  %s = <new_value>;    // Effect first\n"+
						"  addr.call{value: x}(\"\");  // Interaction after",
					sym.Name, sym.Name,
				),
				Filepath: filepath,
				Line:     lineNumber,
				CodeSnippet: fmt.Sprintf(
					"%s.%s: %s %s after external call",
					fnInfo.contractName, fnInfo.functionName,
					sym.Name, fnInfo.lastWriteOperator,
				),
				Severity:   analyzer.Critical,
				Confidence: analyzer.ConfidenceHigh,
				Tags:       []string{"reentrancy", "cei-violation", "state-variable", "external-call"},
			})
		}
	}

	return findings, nil
}

type functionInfo struct {
	contractName        string
	functionName        string
	hasNonReentrant     bool
	contractHasGuard    bool
	writeAfterCallCount int
	lastWriteOperator   string
}

func (d *ReentrancySymbolTableDetector) findProblematicFunctions(
	sym *symboltable.Symbol,
	table *symboltable.SymbolTable,
) []functionInfo {

	fnWrites := make(map[string]*functionInfo)

	for _, write := range sym.Writes {
		if !write.AfterCall {
			continue
		}

		key := write.InFunction
		if key == "" {
			continue
		}

		if _, exists := fnWrites[key]; !exists {
			fnScope := table.FindFunctionScope(write.ScopeID)
			hasGuard := false
			hasNonReentrant := false
			contractName := ""

			if fnScope != nil {
				contractScope := fnScope.ContractScope()
				if contractScope != nil {
					contractName = contractScope.Name
					hasGuard = table.ContractInheritsFrom(contractScope.Name, "ReentrancyGuard")
				}
				hasNonReentrant = table.FunctionHasModifier(fnScope.Name, contractName, "nonReentrant")
			}

			fnWrites[key] = &functionInfo{
				contractName:     contractName,
				functionName:     key,
				hasNonReentrant:  hasNonReentrant,
				contractHasGuard: hasGuard,
			}
		}
		fnWrites[key].writeAfterCallCount++
	}

	result := make([]functionInfo, 0, len(fnWrites))
	for _, info := range fnWrites {
		result = append(result, *info)
	}
	return result
}
