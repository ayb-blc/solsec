package detectors_test

import (
	"strings"
	"testing"

	"github.com/ayb-blc/solsec/internal/analyzer"
	"github.com/ayb-blc/solsec/internal/detectors"
)

// --- Reentrancy V2 Tests ---

func TestReentrancyV2_DetectsClassicCEIViolation(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
contract T {
    mapping(address => uint256) balances;
    function withdraw() external {
        uint256 amt = balances[msg.sender];
        require(amt > 0);
        (bool ok,) = msg.sender.call{value: amt}("");
        require(ok);
        balances[msg.sender] = 0;
    }
}`
	d := detectors.NewReentrancyDetectorV2()
	findings := mustAnalyze(t, d, source)

	if len(findings) == 0 {
		t.Fatal("expected reentrancy finding")
	}
	if findings[0].Severity != analyzer.Critical {
		t.Errorf("severity = %v, want Critical", findings[0].Severity)
	}
}

func TestReentrancyV2_SafeWithNonReentrant(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
contract T is ReentrancyGuard {
    mapping(address => uint256) balances;
    function withdraw() external nonReentrant {
        uint256 amt = balances[msg.sender];
        balances[msg.sender] = 0;
        (bool ok,) = msg.sender.call{value: amt}("");
        require(ok);
    }
}`
	d := detectors.NewReentrancyDetectorV2()
	findings := mustAnalyze(t, d, source)

	if len(findings) != 0 {
		t.Errorf("nonReentrant should suppress finding, got %d findings", len(findings))
	}
}

func TestReentrancyV2_SafeWithCustomMutex(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
contract T {
    bool private locked;
    mapping(address => uint256) balances;
    function withdraw() external {
        require(!locked, "reentrant");
        locked = true;
        uint256 amt = balances[msg.sender];
        balances[msg.sender] = 0;
        (bool ok,) = msg.sender.call{value: amt}("");
        require(ok);
        locked = false;
    }
}`
	d := detectors.NewReentrancyDetectorV2()
	findings := mustAnalyze(t, d, source)

	if len(findings) != 0 {
		t.Errorf("custom mutex should suppress finding, got %d findings", len(findings))
	}
}

func TestReentrancyV2_SafeWithCorrectCEI(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
contract T {
    mapping(address => uint256) balances;
    function withdraw() external {
        uint256 amt = balances[msg.sender];
        require(amt > 0);
        balances[msg.sender] = 0;   // Effect BEFORE interaction
        (bool ok,) = msg.sender.call{value: amt}("");
        require(ok);
    }
}`
	d := detectors.NewReentrancyDetectorV2()
	findings := mustAnalyze(t, d, source)

	if len(findings) != 0 {
		t.Errorf("correct CEI should not trigger, got %d findings", len(findings))
	}
}

func TestReentrancyV2_CrossFunction(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
contract T {
    mapping(address => uint256) balances;

    function withdraw() external {
        _sendFunds(msg.sender, balances[msg.sender]);
        balances[msg.sender] = 0;  // state update AFTER internal call
    }

    function _sendFunds(address to, uint256 amt) internal {
        (bool ok,) = to.call{value: amt}("");
        require(ok);
    }
}`
	d := detectors.NewReentrancyDetectorV2()
	findings := mustAnalyze(t, d, source)

	if len(findings) == 0 {
		t.Fatal("cross-function reentrancy should be detected")
	}
}

func TestReentrancyV2_ViewFunctionIgnored(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
interface IOracle {
    function getPrice() external view returns (uint256);
}
contract T {
    IOracle oracle;
    function getPrice() external view returns (uint256) {
        return oracle.getPrice();
    }
}`
	d := detectors.NewReentrancyDetectorV2()
	findings := mustAnalyze(t, d, source)

	if len(findings) != 0 {
		t.Errorf("view function should not trigger reentrancy, got %d findings", len(findings))
	}
}

// --- Unchecked Call V2 Tests ---

func TestUncheckedCallV2_SafePattern(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
contract T {
    function send(address to, uint256 amt) external {
        (bool ok,) = to.call{value: amt}("");
        require(ok, "Transfer failed");
    }
}`
	d := detectors.NewUncheckedCallDetectorV2()
	findings := mustAnalyze(t, d, source)

	if len(findings) != 0 {
		t.Errorf("checked call should not trigger, got %d findings", len(findings))
	}
}

func TestUncheckedCallV2_UnsafeStandalone(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
contract T {
    function bad(address to, uint256 amt) external {
        to.call{value: amt}("");
    }
}`
	d := detectors.NewUncheckedCallDetectorV2()
	findings := mustAnalyze(t, d, source)

	if len(findings) == 0 {
		t.Fatal("standalone call without return check should trigger")
	}
}

func TestUncheckedCallV2_CapturedButNotChecked(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
contract T {
    function bad(address to, uint256 amt) external {
        (bool ok,) = to.call{value: amt}("");
        // ok is never used!
        emit Sent(to, amt);
    }
}`
	d := detectors.NewUncheckedCallDetectorV2()
	findings := mustAnalyze(t, d, source)

	if len(findings) == 0 {
		t.Fatal("captured but unchecked return should trigger")
	}
}

func TestUncheckedCallV2_RequireInlineCall(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
contract T {
    function safe(address to, uint256 amt) external {
        require(payable(to).send(amt), "send failed");
    }
}`
	d := detectors.NewUncheckedCallDetectorV2()
	findings := mustAnalyze(t, d, source)

	if len(findings) != 0 {
		t.Errorf("require(addr.send()) is safe, got %d findings", len(findings))
	}
}

func TestUncheckedCallV2_IfNotRevert(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
contract T {
    function safe(address to, uint256 amt) external {
        if (!payable(to).send(amt)) revert("send failed");
    }
}`
	d := detectors.NewUncheckedCallDetectorV2()
	findings := mustAnalyze(t, d, source)

	if len(findings) != 0 {
		t.Errorf("if(!send()) revert is safe, got %d findings", len(findings))
	}
}

// --- Version Awareness Tests ---

func TestParseVersion_Caret(t *testing.T) {
	source := `pragma solidity ^0.8.0;`
	v, err := detectors.ParseVersion(source)
	if err != nil {
		t.Fatal(err)
	}
	if v.Minor != 8 {
		t.Errorf("minor = %d, want 8", v.Minor)
	}
	if v.MightBeBelow08() {
		t.Error("^0.8.0 should not be considered below 0.8")
	}
	if !v.HasBuiltinOverflowProtection() {
		t.Error("^0.8.0 should have overflow protection")
	}
}

func TestParseVersion_OldVersion(t *testing.T) {
	source := `pragma solidity ^0.7.6;`
	v, err := detectors.ParseVersion(source)
	if err != nil {
		t.Fatal(err)
	}
	if !v.MightBeBelow08() {
		t.Error("^0.7.6 should be considered below 0.8")
	}
	if v.HasBuiltinOverflowProtection() {
		t.Error("^0.7.6 should NOT have overflow protection")
	}
}

func TestParseVersion_RangeConstraint(t *testing.T) {
	source := `pragma solidity >=0.6.0 <0.9.0;`
	v, err := detectors.ParseVersion(source)
	if err != nil {
		t.Fatal(err)
	}
	if !v.MightBeBelow08() {
		t.Error(">=0.6.0 might be below 0.8")
	}
}

func TestOverflowV2_Pre08NoSafeMath(t *testing.T) {
	source := `
pragma solidity ^0.7.0;
contract T {
    mapping(address => uint256) balances;
    function deposit(uint256 amt) external {
        balances[msg.sender] += amt;
    }
}`
	d := detectors.NewIntegerOverflowDetectorV2()
	findings := mustAnalyze(t, d, source)

	if len(findings) == 0 {
		t.Fatal("pre-0.8 += without SafeMath should trigger overflow finding")
	}
}

func TestOverflowV2_Pre08WithSafeMath(t *testing.T) {
	source := `
pragma solidity ^0.7.0;
import "@openzeppelin/contracts/utils/math/SafeMath.sol";
contract T {
    using SafeMath for uint256;
    mapping(address => uint256) balances;
    function deposit(uint256 amt) external {
        balances[msg.sender] = balances[msg.sender].add(amt);
    }
}`
	d := detectors.NewIntegerOverflowDetectorV2()
	findings := mustAnalyze(t, d, source)

	if len(findings) != 0 {
		t.Errorf("SafeMath usage should suppress finding, got %d", len(findings))
	}
}

func TestOverflowV2_Post08NoUnchecked(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
contract T {
    mapping(address => uint256) balances;
    function deposit(uint256 amt) external {
        balances[msg.sender] += amt;
    }
}`
	d := detectors.NewIntegerOverflowDetectorV2()
	findings := mustAnalyze(t, d, source)

	if len(findings) != 0 {
		t.Errorf("0.8+ without unchecked should not trigger, got %d", len(findings))
	}
}

func TestOverflowV2_Post08WithUnchecked(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
contract T {
    mapping(address => uint256) balances;
    function unsafeAdd(address user, uint256 amt) external {
        unchecked {
            balances[user] += amt;
        }
    }
}`
	d := detectors.NewIntegerOverflowDetectorV2()
	findings := mustAnalyze(t, d, source)

	if len(findings) == 0 {
		t.Fatal("unchecked += in 0.8+ should trigger")
	}
}

func TestOverflowV2_UnsafeDowncast(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
contract T {
    function cast(uint256 x) external returns (uint8) {
        return uint8(x);
    }
}`
	d := detectors.NewIntegerOverflowDetectorV2()
	findings := mustAnalyze(t, d, source)

	if len(findings) == 0 {
		t.Fatal("uint8(x) downcast should trigger")
	}
}

func TestOverflowV2_SafeConstantDowncast(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
contract T {
    uint8 constant MAX = uint8(255);
}`
	d := detectors.NewIntegerOverflowDetectorV2()
	findings := mustAnalyze(t, d, source)

	if len(findings) != 0 {
		t.Errorf("constant downcast should not trigger, got %d", len(findings))
	}
}

// --- Helpers ---

func mustAnalyze(t *testing.T, d interface {
	Analyze([]string, string, string) ([]analyzer.Finding, error)
}, source string) []analyzer.Finding {
	t.Helper()
	lines := strings.Split(source, "\n")
	findings, err := d.Analyze(lines, source, "test.sol")
	if err != nil {
		t.Fatalf("Analyze error: %v", err)
	}
	return findings
}
