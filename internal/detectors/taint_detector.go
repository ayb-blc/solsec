package detectors

import (
	"fmt"
	"strings"

	"github.com/ayb-blc/solsec/internal/analyzer"
	"github.com/ayb-blc/solsec/internal/parser"
	"github.com/ayb-blc/solsec/internal/symboltable"
	"github.com/ayb-blc/solsec/internal/taint"
)

type TaintDetector struct{}

func NewTaintDetector() *TaintDetector { return &TaintDetector{} }

func (d *TaintDetector) Name() string                { return "taint-analysis" }
func (d *TaintDetector) Severity() analyzer.Severity { return analyzer.High }
func (d *TaintDetector) Description() string {
	return "Tracks tainted values (msg.sender, msg.value, calldata) to dangerous sinks"
}

func (d *TaintDetector) AnalyzeWithTaint(
	flows []taint.TaintFlow,
	table *symboltable.SymbolTable,
	unit *parser.SourceUnit,
	filepath string,
) ([]analyzer.Finding, error) {

	var findings []analyzer.Finding

	seen := make(map[string]bool)

	for _, flow := range flows {
		key := fmt.Sprintf("%s:%s:%s:%s",
			flow.ContractName, flow.FunctionName,
			flow.SourceLabel, flow.SinkKind,
		)
		if seen[key] {
			continue
		}
		seen[key] = true

		finding := d.flowToFinding(flow, filepath, table)
		if finding != nil {
			findings = append(findings, *finding)
		}
	}

	return findings, nil
}

func (d *TaintDetector) flowToFinding(
	flow taint.TaintFlow,
	filepath string,
	_ *symboltable.SymbolTable,
) *analyzer.Finding {

	severity, confidence := d.assessRisk(flow)

	// Propagation path'i okunabilir hale getir
	chainStr := buildChainString(flow)

	description, recommendation := d.buildDescriptionAndRecommendation(flow, chainStr)

	// Sink-specific title
	title := d.buildTitle(flow)

	// Tag'ler
	tags := buildTags(flow)

	return &analyzer.Finding{
		DetectorName:   d.Name(),
		Title:          title,
		Description:    description,
		Recommendation: recommendation,
		Filepath:       filepath,
		Severity:       severity,
		Confidence:     confidence,
		Tags:           tags,
	}
}

// assessRisk determines the risk level for one taint flow.
func (d *TaintDetector) assessRisk(flow taint.TaintFlow) (analyzer.Severity, analyzer.Confidence) {
	var severity analyzer.Severity
	switch flow.SinkKind {
	case taint.SinkSelfdestruct:
		severity = analyzer.Critical
	case taint.SinkDelegatecall:
		severity = analyzer.Critical
	case taint.SinkExternalCall:
		severity = analyzer.High
	case taint.SinkETHTransfer:
		severity = analyzer.High
	case taint.SinkStorageWrite:
		severity = analyzer.High
	case taint.SinkAccessControl:
		severity = analyzer.Medium
	case taint.SinkArithmeticOp:
		severity = analyzer.Medium
	default:
		severity = analyzer.Low
	}

	var confidence analyzer.Confidence
	switch {
	case flow.SourceLabel == taint.TaintMsgValue &&
		(flow.SinkKind == taint.SinkETHTransfer || flow.SinkKind == taint.SinkExternalCall):
		confidence = analyzer.ConfidenceHigh

	case flow.SourceLabel == taint.TaintMsgSender &&
		flow.SinkKind == taint.SinkSelfdestruct:
		confidence = analyzer.ConfidenceHigh

	case flow.SourceLabel == taint.TaintDerived:
		confidence = analyzer.ConfidenceMedium // Derived taint daha az kesin

	default:
		confidence = analyzer.ConfidenceMedium
	}

	return severity, confidence
}

func (d *TaintDetector) buildTitle(flow taint.TaintFlow) string {
	return fmt.Sprintf(
		"%s: %s flows to %s in %s.%s",
		flow.SinkKind,
		flow.SourceLabel,
		flow.SinkKind,
		flow.ContractName,
		flow.FunctionName,
	)
}

func (d *TaintDetector) buildDescriptionAndRecommendation(
	flow taint.TaintFlow,
	chainStr string,
) (string, string) {

	switch flow.SinkKind {

	case taint.SinkETHTransfer:
		return fmt.Sprintf(
				"User-controlled value (%s) flows into an ETH transfer in '%s.%s'.\n\n"+
					"Propagation: %s\n\n"+
					"An attacker can manipulate the transfer amount by controlling the input value. "+
					"Combined with reentrancy, this could drain contract funds.",
				flow.SourceLabel, flow.ContractName, flow.FunctionName, chainStr,
			),
			"Validate the transfer amount against expected bounds:\n" +
				"  require(amount <= maxWithdrawal, \"Exceeds limit\");\n" +
				"  require(amount <= balances[msg.sender], \"Insufficient balance\");\n" +
				"Apply CEI pattern and use ReentrancyGuard."

	case taint.SinkExternalCall:
		return fmt.Sprintf(
				"User-controlled value (%s) is passed to an external call in '%s.%s'.\n\n"+
					"Propagation: %s\n\n"+
					"The attacker controls data or value sent in the external call. "+
					"This can lead to fund manipulation or unexpected contract interactions.",
				flow.SourceLabel, flow.ContractName, flow.FunctionName, chainStr,
			),
			"Validate all inputs before external calls. " +
				"Consider using a whitelist for allowed contracts/addresses. " +
				"Apply CEI pattern."

	case taint.SinkSelfdestruct:
		return fmt.Sprintf(
				"CRITICAL: User-controlled value (%s) flows to selfdestruct in '%s.%s'.\n\n"+
					"Propagation: %s\n\n"+
					"If an attacker controls the address passed to selfdestruct, "+
					"they can potentially destroy the contract and redirect all ETH to an arbitrary address.",
				flow.SourceLabel, flow.ContractName, flow.FunctionName, chainStr,
			),
			"Never allow user-controlled input to reach selfdestruct. " +
				"Add strict access control:\n" +
				"  require(msg.sender == owner, \"Not authorized\");\n" +
				"  selfdestruct(payable(owner)); // Only owner's address"

	case taint.SinkDelegatecall:
		return fmt.Sprintf(
				"CRITICAL: User-controlled value (%s) flows to delegatecall in '%s.%s'.\n\n"+
					"Propagation: %s\n\n"+
					"delegatecall executes code in the context of the calling contract. "+
					"If the target address or calldata is attacker-controlled, "+
					"the attacker can execute arbitrary code with full access to contract storage.",
				flow.SourceLabel, flow.ContractName, flow.FunctionName, chainStr,
			),
			"Never allow user input to control delegatecall target address. " +
				"Use a whitelist of approved implementation contracts. " +
				"Consider using OpenZeppelin's upgradeable proxy patterns."

	case taint.SinkAccessControl:
		return fmt.Sprintf(
				"User-controlled value (%s) is used in an access control check in '%s.%s'.\n\n"+
					"Propagation: %s\n\n"+
					"The access control condition depends on user input, "+
					"which may allow bypassing authorization checks.",
				flow.SourceLabel, flow.ContractName, flow.FunctionName, chainStr,
			),
			"Access control checks should compare against trusted state variables (owner, roles), " +
				"not user-supplied input. " +
				"Use OpenZeppelin's Ownable or AccessControl patterns."

	default:
		return fmt.Sprintf(
			"Tainted value (%s) reaches a potentially dangerous operation in '%s.%s'.\n"+
				"Propagation: %s",
			flow.SourceLabel, flow.ContractName, flow.FunctionName, chainStr,
		), "Review the data flow and validate inputs before use."
	}
}

func buildChainString(flow taint.TaintFlow) string {
	parts := []string{flow.SourceLabel.String()}
	for _, sym := range flow.Chain {
		parts = append(parts, sym.Name)
	}
	parts = append(parts, fmt.Sprintf("[%s]", flow.SinkKind))
	return strings.Join(parts, " → ")
}

func buildTags(flow taint.TaintFlow) []string {
	tags := []string{
		"taint-analysis",
		flow.SourceLabel.String(),
		flow.SinkKind.String(),
	}
	if len(flow.Chain) > 0 {
		tags = append(tags, "propagation")
	}
	return tags
}
