package suppression_test

import (
	"testing"

	"github.com/ayb-blc/solsec/internal/rules"
	"github.com/ayb-blc/solsec/internal/suppression"
)

func TestInlineParser_NextLine(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
contract T {
    // solsec-disable-next-line SOLSEC-REENTRANCY-001
    function withdraw() external {
        msg.sender.call{value: 1}("");
    }
}`
	parser := suppression.NewInlineSuppressionParser()
	fs := parser.Parse(source)

	if !fs.IsSuppressed(rules.IDReentrancy001, 5) {
		t.Error("line 5 should be suppressed by next-line directive on line 4")
	}
	if fs.IsSuppressed(rules.IDReentrancy001, 4) {
		t.Error("line 4 (the directive itself) should not be suppressed")
	}
	if fs.IsSuppressed(rules.IDReentrancy001, 6) {
		t.Error("line 6 should not be suppressed (directive only applies to next line)")
	}
}

func TestInlineParser_MultipleRules(t *testing.T) {
	source := `// solsec-disable-next-line SOLSEC-REENTRANCY-001, SOLSEC-AUTH-001
function bad() external {}`

	parser := suppression.NewInlineSuppressionParser()
	fs := parser.Parse(source)

	if !fs.IsSuppressed(rules.IDReentrancy001, 2) {
		t.Error("REENTRANCY-001 should be suppressed on line 2")
	}
	if !fs.IsSuppressed(rules.IDTxOrigin001, 2) {
		t.Error("AUTH-001 should be suppressed on line 2")
	}
	if fs.IsSuppressed(rules.IDAccessControl001, 2) {
		t.Error("ACCESS-001 should NOT be suppressed")
	}
}

func TestInlineParser_AllKeyword(t *testing.T) {
	source := `// solsec-disable-next-line all
function bad() external {}`

	parser := suppression.NewInlineSuppressionParser()
	fs := parser.Parse(source)

	if !fs.IsSuppressed(rules.IDReentrancy001, 2) {
		t.Error("all rules should be suppressed on line 2")
	}
	if !fs.IsSuppressed(rules.IDAccessControl001, 2) {
		t.Error("all rules should be suppressed on line 2")
	}
}

func TestInlineParser_DisableEnableBlock(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
// solsec-disable SOLSEC-REENTRANCY-001
function one() external { msg.sender.call("");}
function two() external { msg.sender.call("");}
// solsec-enable SOLSEC-REENTRANCY-001
function three() external { msg.sender.call("");}`

	parser := suppression.NewInlineSuppressionParser()
	fs := parser.Parse(source)

	if !fs.IsSuppressed(rules.IDReentrancy001, 4) {
		t.Error("line 4 should be suppressed (in disable block)")
	}
	if !fs.IsSuppressed(rules.IDReentrancy001, 5) {
		t.Error("line 5 should be suppressed (in disable block)")
	}
	if fs.IsSuppressed(rules.IDReentrancy001, 7) {
		t.Error("line 7 should NOT be suppressed (after enable)")
	}
}

func TestInlineParser_UnclosedBlock(t *testing.T) {
	source := `
// solsec-disable SOLSEC-REENTRANCY-001
function bad1() external {}
function bad2() external {}`

	parser := suppression.NewInlineSuppressionParser()
	fs := parser.Parse(source)

	if !fs.IsSuppressed(rules.IDReentrancy001, 3) {
		t.Error("line 3 should be suppressed (unclosed block)")
	}
	if !fs.IsSuppressed(rules.IDReentrancy001, 4) {
		t.Error("line 4 should be suppressed (unclosed block, file end)")
	}
}

func TestInlineParser_VyperHashComment(t *testing.T) {
	source := `# solsec-disable-next-line SOLSEC-REENTRANCY-001
def withdraw():
    send(msg.sender, 1)`

	parser := suppression.NewInlineSuppressionParser()
	fs := parser.Parse(source)

	if !fs.IsSuppressed(rules.IDReentrancy001, 2) {
		t.Error("Vyper # comment directive should work")
	}
}

func TestFormatDirective_Solidity(t *testing.T) {
	directive := suppression.FormatDirective(rules.IDReentrancy001, "solidity")
	expected := "// solsec-disable-next-line SOLSEC-REENTRANCY-001"
	if directive != expected {
		t.Errorf("directive = %q, want %q", directive, expected)
	}
}

func TestFormatDirective_Vyper(t *testing.T) {
	directive := suppression.FormatDirective(rules.IDReentrancy001, "vyper")
	expected := "# solsec-disable-next-line SOLSEC-REENTRANCY-001"
	if directive != expected {
		t.Errorf("directive = %q, want %q", directive, expected)
	}
}
