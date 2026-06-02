package formal

import (
	"fmt"
	"strings"

	"github.com/ayb-blc/solsec/internal/analyzer"
)

// SeedGenerator creates formal-verification targets from static-analysis findings.
type SeedGenerator struct {
	propertyTemplates map[PropertyKind]propertyTemplate
}

type propertyTemplate struct {
	echidnaTemplate   string
	manticoreTemplate string
}

func NewSeedGenerator() *SeedGenerator {
	sg := &SeedGenerator{
		propertyTemplates: make(map[PropertyKind]propertyTemplate),
	}
	sg.registerTemplates()
	return sg
}

func (sg *SeedGenerator) registerTemplates() {
	sg.propertyTemplates[PropertyReentrancy] = propertyTemplate{
		echidnaTemplate: `
// Echidna property: reentrancy invariant for {{.FunctionName}}
// solsec finding: {{.FindingTitle}}
function echidna_no_reentrancy_{{.FunctionName}}() public returns (bool) {
    uint256 balanceBefore = address(this).balance;
    try this.{{.FunctionName}}() {} catch {}
    // Balance should not decrease unexpectedly
    return address(this).balance >= balanceBefore || _reentrancyDetected == false;
}`,
		manticoreTemplate: `
# Manticore analysis: reentrancy in {{.FunctionName}}
# solsec finding: {{.FindingTitle}}
from manticore.ethereum import ManticoreEVM

m = ManticoreEVM()
contract = m.solidity_create_contract(source, owner=m.make_account(balance=10**18))

# Symbolic attacker
attacker = m.make_account(balance=10**18)

# Trigger {{.FunctionName}} with symbolic input
amount = m.make_symbolic_value()
m.transaction(caller=attacker, address=contract, data=ABI.function_call("{{.FunctionName}}", amount))

# Check for balance inconsistency
for state in m.ready_states:
    with state as tmp:
        balance = tmp.platform.get_balance(contract.address)
        tmp.constrain(balance < 0)  # Should be UNSAT
        if tmp.is_feasible():
            print("REENTRANCY FOUND")
            m.generate_testcase(state, "reentrancy")
`,
	}

	sg.propertyTemplates[PropertyAccessControl] = propertyTemplate{
		echidnaTemplate: `
// Echidna property: access control for {{.FunctionName}}
// solsec finding: {{.FindingTitle}}
address private _owner;
bool private _accessViolation = false;

function echidna_access_control_{{.FunctionName}}() public returns (bool) {
    if (msg.sender != _owner) {
        try this.{{.FunctionName}}() {
            _accessViolation = true;
        } catch {}
    }
    return !_accessViolation;
}`,
		manticoreTemplate: `
# Manticore: access control verification for {{.FunctionName}}
from manticore.ethereum import ManticoreEVM
from manticore.core.smtlib import operators

m = ManticoreEVM()
owner = m.make_account(balance=10**18)
contract = m.solidity_create_contract(source, owner=owner)

# Non-owner attacker
attacker = m.make_account(balance=10**18)

# Try calling restricted function as non-owner
m.transaction(caller=attacker, address=contract,
               data=ABI.function_call("{{.FunctionName}}"))

for state in m.ready_states:
    print(f"State {state.id}: checking access control")
    m.generate_testcase(state, "access_control")
`,
	}

	sg.propertyTemplates[PropertyArithmetic] = propertyTemplate{
		echidnaTemplate: `
// Echidna property: arithmetic safety for {{.FunctionName}}
// solsec finding: {{.FindingTitle}}
function echidna_no_overflow_{{.FunctionName}}() public returns (bool) {
    uint256 before = totalSupply;
    uint256 maxAmount = type(uint256).max / 2;
    try this.{{.FunctionName}}(maxAmount) {} catch {}
    // totalSupply should never overflow
    return totalSupply >= before || totalSupply == 0;
}`,
		manticoreTemplate: `
# Manticore: arithmetic verification for {{.FunctionName}}
from manticore.ethereum import ManticoreEVM

m = ManticoreEVM()
contract = m.solidity_create_contract(source, owner=m.make_account())

# Symbolic large value
amount = m.make_symbolic_value()
m.transaction(data=ABI.function_call("{{.FunctionName}}", amount))

for state in m.ready_states:
    # Check for overflow condition
    with state as tmp:
        supply = tmp.platform.get_storage_data(contract.address, 0)
        tmp.constrain(supply == 0)
        if tmp.is_feasible():
            print("ARITHMETIC VIOLATION")
            m.generate_testcase(state, "arithmetic")
`,
	}

	sg.propertyTemplates[PropertyETHBalance] = propertyTemplate{
		echidnaTemplate: `
// Echidna property: ETH balance invariant
// solsec finding: {{.FindingTitle}}
function echidna_balance_preserved() public payable returns (bool) {
    uint256 totalDeposits = 0;
    // Sum all user deposits
    for (uint i = 0; i < users.length; i++) {
        totalDeposits += balances[users[i]];
    }
    // Contract ETH balance >= total deposits
    return address(this).balance >= totalDeposits;
}`,
		manticoreTemplate: "",
	}
}

func (sg *SeedGenerator) Generate(findings []analyzer.Finding) []*FuzzTarget {
	var targets []*FuzzTarget

	sorted := sortByPriority(findings)

	for i := range sorted {
		f := &sorted[i]
		target := sg.findingToTarget(f)
		if target != nil {
			targets = append(targets, target)
		}
	}

	return targets
}

func (sg *SeedGenerator) findingToTarget(f *analyzer.Finding) *FuzzTarget {
	target := &FuzzTarget{
		ContractPath:  f.Filepath,
		FunctionName:  extractFunctionName(f),
		SourceFinding: f,
		Priority:      severityToPriority(f.Severity),
	}

	target.ContractName = contractNameFromPath(f.Filepath)

	switch f.DetectorName {
	case "reentrancy", "reentrancy-ast", "reentrancy-symtable", "reentrancy-inter":
		target.Properties = sg.reentrancyProperties(f, target)
		target.SeedValues = sg.reentrancySeedValues(f)

	case "access-control":
		target.Properties = sg.accessControlProperties(f, target)
		target.SeedValues = sg.accessControlSeedValues()

	case "integer-overflow":
		target.Properties = sg.arithmeticProperties(f, target)
		target.SeedValues = sg.arithmeticSeedValues()

	case "unchecked-call":
		target.Properties = sg.ethBalanceProperties(f, target)
		target.SeedValues = sg.ethBalanceSeedValues()

	case "delegatecall":
		target.Properties = sg.delegatecallProperties(f, target)
		target.SeedValues = sg.delegatecallSeedValues()

	default:
		return nil
	}

	if len(target.Properties) == 0 {
		return nil
	}

	return target
}

func (sg *SeedGenerator) reentrancyProperties(
	f *analyzer.Finding,
	target *FuzzTarget,
) []FuzzProperty {
	tmpl := sg.propertyTemplates[PropertyReentrancy]
	fnName := target.FunctionName
	if fnName == "" {
		fnName = "withdraw"
	}

	return []FuzzProperty{
		{
			Name:        "no_reentrancy_" + fnName,
			Description: fmt.Sprintf("Contract balance must not decrease via reentrancy in %s", fnName),
			SolidityCode: sg.renderTemplate(tmpl.echidnaTemplate, map[string]string{
				"FunctionName": fnName,
				"FindingTitle": f.Title,
			}),
			PythonCode: sg.renderTemplate(tmpl.manticoreTemplate, map[string]string{
				"FunctionName": fnName,
				"FindingTitle": f.Title,
			}),
			Kind: PropertyReentrancy,
		},
	}
}

func (sg *SeedGenerator) reentrancySeedValues(_ *analyzer.Finding) []SeedValue {
	return []SeedValue{
		{
			ParamName: "amount",
			Value:     "1000000000000000000", // 1 ETH in wei
			Reason:    "typical withdrawal amount for reentrancy testing",
		},
		{
			ParamName: "amount",
			Value:     "1",
			Reason:    "minimum amount — edge case for reentrancy",
		},
		{
			ParamName: "amount",
			Value:     fmt.Sprintf("%d", ^uint64(0)),
			Reason:    "max uint64 — potential overflow combined with reentrancy",
		},
	}
}

func (sg *SeedGenerator) accessControlProperties(
	f *analyzer.Finding,
	target *FuzzTarget,
) []FuzzProperty {
	tmpl := sg.propertyTemplates[PropertyAccessControl]
	fnName := target.FunctionName
	if fnName == "" {
		fnName = extractFunctionName(f)
	}

	return []FuzzProperty{
		{
			Name:        "access_control_" + fnName,
			Description: fmt.Sprintf("Only authorized callers should be able to call %s", fnName),
			SolidityCode: sg.renderTemplate(tmpl.echidnaTemplate, map[string]string{
				"FunctionName": fnName,
				"FindingTitle": f.Title,
			}),
			PythonCode: sg.renderTemplate(tmpl.manticoreTemplate, map[string]string{
				"FunctionName": fnName,
				"FindingTitle": f.Title,
			}),
			Kind: PropertyAccessControl,
		},
	}
}

func (sg *SeedGenerator) accessControlSeedValues() []SeedValue {
	return []SeedValue{
		{
			ParamName: "caller",
			Value:     "0x0000000000000000000000000000000000000001",
			Reason:    "non-zero non-owner address",
		},
		{
			ParamName: "caller",
			Value:     "0xffffffffffffffffffffffffffffffffffffffff",
			Reason:    "max address — edge case",
		},
	}
}

func (sg *SeedGenerator) arithmeticProperties(
	f *analyzer.Finding,
	target *FuzzTarget,
) []FuzzProperty {
	tmpl := sg.propertyTemplates[PropertyArithmetic]
	fnName := target.FunctionName
	if fnName == "" {
		fnName = "transfer"
	}

	return []FuzzProperty{
		{
			Name:        "no_overflow_" + fnName,
			Description: "Arithmetic operations must not overflow",
			SolidityCode: sg.renderTemplate(tmpl.echidnaTemplate, map[string]string{
				"FunctionName": fnName,
				"FindingTitle": f.Title,
			}),
			PythonCode: sg.renderTemplate(tmpl.manticoreTemplate, map[string]string{
				"FunctionName": fnName,
				"FindingTitle": f.Title,
			}),
			Kind: PropertyArithmetic,
		},
	}
}

func (sg *SeedGenerator) arithmeticSeedValues() []SeedValue {
	return []SeedValue{
		{
			ParamName: "amount",
			Value:     "115792089237316195423570985008687907853269984665640564039457584007913129639935",
			Reason:    "uint256 max — overflow boundary",
		},
		{
			ParamName: "amount",
			Value:     "57896044618658097711785492504343953926634992332820282019728792003956564819968",
			Reason:    "uint256 max/2 — midpoint",
		},
		{
			ParamName: "amount",
			Value:     "0",
			Reason:    "zero — underflow boundary",
		},
	}
}

func (sg *SeedGenerator) ethBalanceProperties(
	f *analyzer.Finding,
	_ *FuzzTarget,
) []FuzzProperty {
	tmpl := sg.propertyTemplates[PropertyETHBalance]
	return []FuzzProperty{
		{
			Name:        "balance_preserved",
			Description: "Contract ETH balance must always cover total user deposits",
			SolidityCode: sg.renderTemplate(tmpl.echidnaTemplate, map[string]string{
				"FindingTitle": f.Title,
			}),
			Kind: PropertyETHBalance,
		},
	}
}

func (sg *SeedGenerator) ethBalanceSeedValues() []SeedValue {
	return []SeedValue{
		{ParamName: "value", Value: "1000000000000000000", Reason: "1 ETH"},
		{ParamName: "value", Value: "0", Reason: "zero ETH — edge case"},
	}
}

func (sg *SeedGenerator) delegatecallProperties(
	f *analyzer.Finding,
	target *FuzzTarget,
) []FuzzProperty {
	return []FuzzProperty{
		{
			Name:        "no_storage_corruption",
			Description: "Delegatecall must not corrupt contract storage",
			SolidityCode: fmt.Sprintf(`
// Echidna: delegatecall storage safety
// Finding: %s
function echidna_storage_not_corrupted() public returns (bool) {
    address ownerBefore = owner;
    // Attempt delegatecall with symbolic target
    try this.%s(address(0), "") {} catch {}
    return owner == ownerBefore;
}`, f.Title, target.FunctionName),
			Kind: PropertyCustom,
		},
	}
}

func (sg *SeedGenerator) delegatecallSeedValues() []SeedValue {
	return []SeedValue{
		{
			ParamName: "target",
			Value:     "0x0000000000000000000000000000000000000000",
			Reason:    "zero address — should revert",
		},
	}
}

func (sg *SeedGenerator) renderTemplate(tmpl string, vars map[string]string) string {
	result := tmpl
	for k, v := range vars {
		result = strings.ReplaceAll(result, "{{."+k+"}}", v)
	}
	return result
}

func extractFunctionName(f *analyzer.Finding) string {
	title := f.Title
	for _, marker := range []string{"in '", "in \"", "function '", "function \""} {
		if idx := strings.Index(title, marker); idx >= 0 {
			rest := title[idx+len(marker):]
			end := strings.IndexAny(rest, "'\"")
			if end > 0 {
				return rest[:end]
			}
		}
	}
	// CodeSnippet'ten dene
	if f.CodeSnippet != "" {
		parts := strings.Fields(f.CodeSnippet)
		for i, p := range parts {
			if p == "function" && i+1 < len(parts) {
				name := parts[i+1]
				if paren := strings.Index(name, "("); paren > 0 {
					return name[:paren]
				}
				return name
			}
		}
	}
	return ""
}

func contractNameFromPath(path string) string {
	base := path
	if idx := strings.LastIndexAny(path, "/\\"); idx >= 0 {
		base = path[idx+1:]
	}
	return strings.TrimSuffix(strings.TrimSuffix(base, ".sol"), ".vy")
}

func severityToPriority(s analyzer.Severity) FuzzPriority {
	switch s {
	case analyzer.Critical:
		return PriorityCritical
	case analyzer.High:
		return PriorityHigh
	case analyzer.Medium:
		return PriorityMedium
	default:
		return PriorityLow
	}
}

func sortByPriority(findings []analyzer.Finding) []analyzer.Finding {
	sorted := make([]analyzer.Finding, len(findings))
	copy(sorted, findings)
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j].Severity > sorted[i].Severity {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}
	return sorted
}
