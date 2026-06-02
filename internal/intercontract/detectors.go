package intercontract

import (
	"fmt"
	"strings"

	"github.com/ayb-blc/solsec/internal/analyzer"
	"github.com/ayb-blc/solsec/internal/parser"
)

type CrossContractDetector struct {
	graph   *CrossContractCallGraph
	project *Project
}

func NewCrossContractDetector(
	graph *CrossContractCallGraph,
	project *Project,
) *CrossContractDetector {
	return &CrossContractDetector{graph: graph, project: project}
}

func (d *CrossContractDetector) Analyze() []analyzer.Finding {
	var findings []analyzer.Finding

	findings = append(findings, d.detectCrossContractReentrancy()...)
	findings = append(findings, d.detectUnprotectedExternalCalls()...)
	findings = append(findings, d.detectPriceManipulation()...)
	findings = append(findings, d.detectAccessControlBypass()...)

	return findings
}

func (d *CrossContractDetector) AnalyzeWithTaint(
	flows []CrossContractTaintFlow,
) []analyzer.Finding {
	findings := d.Analyze()
	findings = append(findings, d.detectTaintFlowFindings(flows)...)
	return findings
}

// --- Detection #1: Cross-Contract Reentrancy ---
func (d *CrossContractDetector) detectCrossContractReentrancy() []analyzer.Finding {
	var findings []analyzer.Finding

	for _, entry := range d.graph.EntryPoints {
		if !entry.TransitiveExternalCall {
			continue
		}

		cycles := d.findReentrancyCycles(entry.ID, make(map[GlobalFunctionID]bool), 0)

		for _, cycle := range cycles {
			if len(cycle) < 2 {
				continue
			}

			hasStateWrite := false
			for _, nodeID := range cycle {
				if node, ok := d.graph.Nodes[nodeID]; ok && node.HasStateWrite {
					hasStateWrite = true
					break
				}
			}

			entryNode := d.graph.Nodes[entry.ID]
			filepath := ""
			if entryNode != nil {
				filepath = entryNode.Filepath
			}

			findings = append(findings, analyzer.Finding{
				DetectorName: "cross-contract-reentrancy",
				Title: fmt.Sprintf(
					"Cross-contract reentrancy: %s → ... → %s",
					cycle[0].Contract(), cycle[len(cycle)-1].Contract(),
				),
				Description: fmt.Sprintf(
					"A reentrancy cycle exists across contract boundaries:\n%s\n\n"+
						"An attacker can exploit this cycle to re-enter '%s' "+
						"before state updates complete.",
					d.formatCycle(cycle),
					entry.ID.Contract(),
				),
				Recommendation: "Apply ReentrancyGuard to all entry points in the cycle. " +
					"Use CEI pattern and consider a cross-contract mutex.",
				Filepath:   filepath,
				Severity:   analyzer.Critical,
				Confidence: analyzer.ConfidenceMedium,
				Tags: []string{
					"reentrancy", "cross-contract",
					boolTag(hasStateWrite, "state-write"),
				},
			})
		}
	}

	return findings
}

func (d *CrossContractDetector) findReentrancyCycles(
	current GlobalFunctionID,
	visited map[GlobalFunctionID]bool,
	depth int,
) [][]GlobalFunctionID {
	if depth > 8 {
		return nil
	}

	var cycles [][]GlobalFunctionID

	node, ok := d.graph.Nodes[current]
	if !ok {
		return nil
	}

	for _, edge := range node.Callees {
		if !edge.CallKind.IsExternal() {
			continue
		}

		callee := edge.Callee

		if visited[callee] {
			// Cycle bulundu
			cycle := []GlobalFunctionID{current, callee}
			cycles = append(cycles, cycle)
			continue
		}

		if callee.Contract() == current.Contract() {
			cycle := []GlobalFunctionID{current, callee}
			cycles = append(cycles, cycle)
			continue
		}

		visited[callee] = true
		subCycles := d.findReentrancyCycles(callee, visited, depth+1)
		for _, sc := range subCycles {
			cycles = append(cycles, append([]GlobalFunctionID{current}, sc...))
		}
		delete(visited, callee)
	}

	return cycles
}

// --- Detection #2: Unprotected External Calls ---
func (d *CrossContractDetector) detectUnprotectedExternalCalls() []analyzer.Finding {
	var findings []analyzer.Finding

	for _, node := range d.graph.Nodes {
		if !node.HasExternalCall {
			continue
		}
		if !node.IsReachableFromExternal {
			continue
		}

		if d.hasAccessControl(node) {
			continue
		}

		for _, edge := range node.Callees {
			if !edge.CallKind.IsExternal() {
				continue
			}

			callee, ok := d.graph.Nodes[edge.Callee]
			if !ok {
				continue
			}

			if !callee.HasStateWrite && !callee.TransitiveStateWrite {
				continue
			}

			findings = append(findings, analyzer.Finding{
				DetectorName: "unprotected-cross-contract-call",
				Title: fmt.Sprintf(
					"Unprotected call from %s to %s.%s",
					node.ID, callee.ContractName, callee.FunctionName,
				),
				Description: fmt.Sprintf(
					"Function '%s' in contract '%s' makes an unprotected external call "+
						"to '%s.%s' which modifies state. "+
						"Without access control, any caller can trigger this cross-contract interaction.",
					node.FunctionName, node.ContractName,
					callee.ContractName, callee.FunctionName,
				),
				Recommendation: fmt.Sprintf(
					"Add access control to '%s.%s' before allowing cross-contract calls:\n"+
						"  modifier onlyAuthorized() { require(authorized[msg.sender]); _; }",
					node.ContractName, node.FunctionName,
				),
				Filepath:   node.Filepath,
				Severity:   analyzer.High,
				Confidence: analyzer.ConfidenceMedium,
				Tags:       []string{"access-control", "cross-contract", "unprotected"},
			})
		}
	}

	return findings
}

// --- Detection #3: Price Manipulation (Read-Only Reentrancy) ---
func (d *CrossContractDetector) detectPriceManipulation() []analyzer.Finding {
	var findings []analyzer.Finding

	oraclePatterns := []string{
		"getPrice", "latestAnswer", "price", "exchangeRate",
		"getReserves", "getAmountOut", "quote", "consult",
	}

	for _, node := range d.graph.Nodes {
		if !node.HasExternalCall {
			continue
		}

		for _, edge := range node.Callees {
			if !edge.CallKind.IsExternal() {
				continue
			}

			callee, ok := d.graph.Nodes[edge.Callee]
			if !ok {
				continue
			}

			isOracle := false
			for _, pattern := range oraclePatterns {
				if strings.Contains(
					strings.ToLower(callee.FunctionName),
					strings.ToLower(pattern),
				) {
					isOracle = true
					break
				}
			}

			if !isOracle {
				continue
			}

			if !node.IsReachableFromExternal {
				continue
			}

			findings = append(findings, analyzer.Finding{
				DetectorName: "price-manipulation-risk",
				Title: fmt.Sprintf(
					"Potential price manipulation: %s queries %s.%s",
					node.ID, callee.ContractName, callee.FunctionName,
				),
				Description: fmt.Sprintf(
					"'%s.%s' queries '%s.%s' for price/rate data. "+
						"If this query occurs during a reentrant call or flash loan, "+
						"the oracle value may reflect a manipulated state.",
					node.ContractName, node.FunctionName,
					callee.ContractName, callee.FunctionName,
				),
				Recommendation: "Use TWAP (time-weighted average price) instead of spot price. " +
					"Add reentrancy protection before oracle queries. " +
					"Consider Chainlink or other manipulation-resistant oracles.",
				Filepath:   node.Filepath,
				Line:       edge.CallLine,
				Severity:   analyzer.High,
				Confidence: analyzer.ConfidenceLow,
				Tags:       []string{"price-manipulation", "oracle", "cross-contract"},
			})
		}
	}

	return findings
}

// --- Detection #4: Access Control Bypass via Proxy ---
func (d *CrossContractDetector) detectAccessControlBypass() []analyzer.Finding {
	var findings []analyzer.Finding

	for _, node := range d.graph.Nodes {
		hasDelegatecall := false
		for _, edge := range node.Callees {
			if edge.CallKind == CrossCallDelegatecall {
				hasDelegatecall = true
				break
			}
		}

		if !hasDelegatecall {
			continue
		}

		for _, edge := range node.Callees {
			if edge.CallKind != CrossCallDelegatecall {
				continue
			}

			calleeNode, ok := d.graph.Nodes[edge.Callee]
			if !ok {
				continue
			}

			if calleeNode.Visibility == parser.VisibilityExternal ||
				calleeNode.Visibility == parser.VisibilityPublic {

				findings = append(findings, analyzer.Finding{
					DetectorName: "proxy-access-control-bypass",
					Title: fmt.Sprintf(
						"Implementation contract %s directly accessible",
						calleeNode.ContractName,
					),
					Description: fmt.Sprintf(
						"Proxy contract '%s' uses delegatecall to '%s.%s', "+
							"but the implementation function is directly callable. "+
							"Attackers can bypass proxy's access control by calling the implementation directly.",
						node.ContractName, calleeNode.ContractName, calleeNode.FunctionName,
					),
					Recommendation: "Initialize the implementation contract to prevent direct calls. " +
						"Add msg.sender == proxy checks in the implementation. " +
						"Use OpenZeppelin's Initializable pattern.",
					Filepath:   node.Filepath,
					Line:       edge.CallLine,
					Severity:   analyzer.High,
					Confidence: analyzer.ConfidenceMedium,
					Tags:       []string{"proxy", "delegatecall", "access-control-bypass"},
				})
			}
		}
	}

	return findings
}

// --- Taint flow finding'leri ---

func (d *CrossContractDetector) detectTaintFlowFindings(
	flows []CrossContractTaintFlow,
) []analyzer.Finding {
	var findings []analyzer.Finding

	for _, flow := range flows {
		if len(flow.Crossings) == 0 {
			continue
		}

		crossingStr := d.formatCrossings(flow.Crossings)
		sourceContract := flow.Crossings[0].FromContract

		filepath := ""
		if file, ok := d.project.ContractFile(sourceContract); ok {
			filepath = file.Path
		}

		findings = append(findings, analyzer.Finding{
			DetectorName: "cross-contract-taint",
			Title: fmt.Sprintf(
				"Tainted value (%s) crosses %d contract boundary(ies) to reach %s sink",
				flow.SourceLabel, len(flow.Crossings), flow.SinkKind,
			),
			Description: fmt.Sprintf(
				"User-controlled value (%s) propagates across contract boundaries:\n%s\n"+
					"This tainted value reaches a %s sink in '%s'.",
				flow.SourceLabel, crossingStr, flow.SinkKind, flow.SinkFunction,
			),
			Recommendation: "Validate user-controlled inputs before passing them across " +
				"contract boundaries. Apply input sanitization at each contract boundary.",
			Filepath:   filepath,
			Severity:   flow.Severity,
			Confidence: analyzer.ConfidenceMedium,
			Tags: []string{
				"taint", "cross-contract",
				flow.SourceLabel.String(),
				flow.SinkKind.String(),
			},
		})
	}

	return findings
}

func (d *CrossContractDetector) hasAccessControl(node *CrossContractNode) bool {
	accessControlModifiers := []string{
		"onlyOwner", "onlyAdmin", "onlyRole", "onlyMinter",
		"onlyOperator", "requiresAuth", "auth", "protected",
		"nonReentrant",
	}
	for _, mod := range node.Modifiers {
		for _, acm := range accessControlModifiers {
			if mod == acm {
				return true
			}
		}
	}
	return false
}

func (d *CrossContractDetector) formatCycle(cycle []GlobalFunctionID) string {
	parts := make([]string, len(cycle))
	for i, id := range cycle {
		parts[i] = string(id)
	}
	return strings.Join(parts, " → ")
}

func (d *CrossContractDetector) formatCrossings(crossings []ContractBoundaryCrossing) string {
	var parts []string
	for _, c := range crossings {
		parts = append(parts, fmt.Sprintf(
			"  %s.%s → %s (via %s call)",
			c.FromContract, c.ViaFunction, c.ToContract, c.CallKind,
		))
	}
	return strings.Join(parts, "\n")
}

func boolTag(condition bool, tag string) string {
	if condition {
		return tag
	}
	return ""
}
