// internal/detectors/dangerous_approve_test.go

package detectors_test

import (
	"strings"
	"testing"

	"github.com/ayb-blc/solsec/internal/analyzer"
	"github.com/ayb-blc/solsec/internal/detectors"
	"github.com/ayb-blc/solsec/internal/testutil"
)

func TestDangerousApprove_Fixtures(t *testing.T) {
	d := detectors.NewDangerousApproveDetector()
	for _, fixture := range testutil.LoadFixtures(t, "../../testdata/fixtures/approve/*.sol") {
		fixture := fixture
		t.Run(fixture.Name, func(t *testing.T) {
			findings, err := d.Analyze(testutil.Lines(fixture.Source), fixture.Source, fixture.Path)
			if err != nil {
				t.Fatalf("Analyze: %v", err)
			}
			if fixture.ExpectedFindings == 0 && len(findings) != 0 {
				t.Fatalf("expected no findings, got %d: %#v", len(findings), findings)
			}
			if fixture.ExpectedFindings > 0 && len(findings) == 0 {
				t.Fatalf("expected at least one finding")
			}
		})
	}
}

func TestDangerousApprove_Critical_UserControlledSpender(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
contract T {
    IERC20 token;
    function approveTo(address spender, uint256 amount) external {
        token.approve(spender, amount);
    }
}`
	d := detectors.NewDangerousApproveDetector()
	findings, _ := d.Analyze(strings.Split(source, "\n"), source, "T.sol")

	if len(findings) == 0 {
		t.Fatal("user-controlled spender = CRITICAL expected")
	}
	critical := false
	for _, f := range findings {
		if f.Severity == analyzer.Critical {
			critical = true
		}
	}
	if !critical {
		t.Error("expected at least one CRITICAL finding")
	}
}

func TestDangerousApprove_Safe_NotUserControlled(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
contract T {
    IERC20 token;
    address public immutable ROUTER;
    function enableTrading() external {
        token.approve(ROUTER, type(uint256).max);
    }
}`
	// ROUTER is immutable — not a function parameter — different check
	// Still should flag for missing access control (HIGH), not CRITICAL
	d := detectors.NewDangerousApproveDetector()
	findings, _ := d.Analyze(strings.Split(source, "\n"), source, "T.sol")

	for _, f := range findings {
		if f.Severity == analyzer.Critical {
			t.Errorf("immutable spender = not CRITICAL, got %v", f.Severity)
		}
	}
}

func TestDangerousApprove_High_MaxUintNoGuard(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
contract T {
    IERC20 token;
    address router;
    function setup() external {
        token.approve(router, type(uint256).max);
    }
}`
	d := detectors.NewDangerousApproveDetector()
	findings, _ := d.Analyze(strings.Split(source, "\n"), source, "T.sol")

	high := false
	for _, f := range findings {
		if f.Severity == analyzer.High {
			high = true
		}
	}
	if !high {
		t.Error("unlimited approve without guard = HIGH expected")
	}
}

func TestDangerousApprove_Safe_MaxUintWithOnlyOwner(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
contract T {
    IERC20 token;
    address router;
    modifier onlyOwner() { require(msg.sender == owner); _; }
    function setup() external onlyOwner {
        token.approve(router, type(uint256).max);
    }
}`
	d := detectors.NewDangerousApproveDetector()
	findings, _ := d.Analyze(strings.Split(source, "\n"), source, "T.sol")

	for _, f := range findings {
		if f.Severity == analyzer.High {
			t.Errorf("onlyOwner protects unlimited approve, got HIGH: %s", f.Title)
		}
	}
}

func TestDangerousApprove_Medium_SafeApproveDeprecated(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
contract T {
    function setup(address token, address spender) external {
        IERC20(token).safeApprove(spender, 1000);
    }
}`
	d := detectors.NewDangerousApproveDetector()
	findings, _ := d.Analyze(strings.Split(source, "\n"), source, "T.sol")

	if len(findings) == 0 {
		t.Fatal("safeApprove = MEDIUM expected")
	}
	found := false
	for _, f := range findings {
		if f.Severity == analyzer.Medium {
			found = true
		}
	}
	if !found {
		t.Error("expected MEDIUM for safeApprove")
	}
}

func TestDangerousApprove_Safe_ForceApprove(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
contract T {
    function setup(address token, address spender, uint256 amount) external {
        SafeERC20.forceApprove(IERC20(token), spender, amount);
    }
}`
	d := detectors.NewDangerousApproveDetector()
	findings, _ := d.Analyze(strings.Split(source, "\n"), source, "T.sol")

	if len(findings) != 0 {
		t.Errorf("forceApprove = safe, got %d findings", len(findings))
	}
}

func TestDangerousApprove_Safe_IncreaseAllowance(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
contract T {
    IERC20 token;
    function addAllowance(address spender, uint256 extra) external {
        token.increaseAllowance(spender, extra);
    }
}`
	d := detectors.NewDangerousApproveDetector()
	findings, _ := d.Analyze(strings.Split(source, "\n"), source, "T.sol")

	if len(findings) != 0 {
		t.Errorf("increaseAllowance = safe, got %d findings", len(findings))
	}
}

func TestDangerousApprove_Safe_Constructor(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
contract T {
    constructor(address token, address router) {
        IERC20(token).approve(router, type(uint256).max);
    }
}`
	d := detectors.NewDangerousApproveDetector()
	findings, _ := d.Analyze(strings.Split(source, "\n"), source, "T.sol")

	for _, f := range findings {
		if f.Severity >= analyzer.High {
			t.Errorf("constructor approve = skip HIGH+, got %v", f.Severity)
		}
	}
}

func TestDangerousApprove_Low_RaceCondition(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
contract T {
    IERC20 token;
    function changeAllowance(address spender, uint256 newAmount) external {
        token.approve(spender, newAmount); // direct change, no zero-first
    }
}`
	d := detectors.NewDangerousApproveDetector()
	findings, _ := d.Analyze(strings.Split(source, "\n"), source, "T.sol")

	if len(findings) == 0 {
		t.Fatal("direct approve without zero-first = at least LOW expected")
	}
}
