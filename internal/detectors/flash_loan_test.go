// internal/detectors/flash_loan_test.go

package detectors_test

import (
	"strings"
	"testing"

	"github.com/ayb-blc/solsec/internal/analyzer"
	"github.com/ayb-blc/solsec/internal/detectors"
	"github.com/ayb-blc/solsec/internal/testutil"
)

func TestFlashLoan_Fixtures(t *testing.T) {
	d := detectors.NewFlashLoanDetector()
	for _, fixture := range testutil.LoadFixtures(t, "../../testdata/fixtures/flash_loan/*.sol") {
		fixture := fixture
		t.Run(fixture.Name, func(t *testing.T) {
			findings, err := d.Analyze(testutil.Lines(fixture.Source), fixture.Source, fixture.Path)
			if err != nil {
				t.Fatalf("Analyze: %v", err)
			}
			if len(findings) != fixture.ExpectedFindings {
				t.Fatalf("findings = %d, want %d: %#v", len(findings), fixture.ExpectedFindings, findings)
			}
		})
	}
}

func TestFlashLoan_ProviderCritical_StateWriteAroundCallback(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
contract Pool {
    uint256 public totalBorrowed;
    function flashLoan(address receiver, uint256 amount) external {
        totalBorrowed += amount;
        IFlashBorrower(receiver).onFlashLoan(amount);
        totalBorrowed -= amount;
    }
}`
	d := detectors.NewFlashLoanDetector()
	findings, _ := d.Analyze(strings.Split(source, "\n"), source, "T.sol")

	if len(findings) == 0 {
		t.Fatal("state writes around callback = CRITICAL expected")
	}
	if findings[0].Severity != analyzer.Critical {
		t.Errorf("severity = %v, want CRITICAL", findings[0].Severity)
	}
	if findings[0].RuleID != "SOLSEC-DEFI-001" {
		t.Errorf("rule = %v, want SOLSEC-DEFI-001", findings[0].RuleID)
	}
}

func TestFlashLoan_ProviderSafe_NonReentrant(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
contract Pool {
    uint256 public totalBorrowed;
    function flashLoan(address receiver, uint256 amount) external nonReentrant {
        totalBorrowed += amount;
        IFlashBorrower(receiver).onFlashLoan(amount);
        totalBorrowed -= amount;
    }
}`
	d := detectors.NewFlashLoanDetector()
	findings, _ := d.Analyze(strings.Split(source, "\n"), source, "T.sol")

	if len(findings) != 0 {
		t.Errorf("nonReentrant = safe, got %d findings", len(findings))
	}
}

func TestFlashLoan_ReceiverVulnerable_NoCallerCheck(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
contract Receiver {
    function onFlashLoan(address, address token, uint256 amount, uint256 fee, bytes calldata) 
        external returns (bytes32) {
        IERC20(token).approve(msg.sender, amount + fee);
        return keccak256("ERC3156FlashBorrower.onFlashLoan");
    }
}`
	d := detectors.NewFlashLoanDetector()
	findings, _ := d.Analyze(strings.Split(source, "\n"), source, "T.sol")

	if len(findings) == 0 {
		t.Fatal("no caller check + token approve = HIGH expected")
	}
	if findings[0].Severity != analyzer.High {
		t.Errorf("severity = %v, want HIGH", findings[0].Severity)
	}
	if findings[0].RuleID != "SOLSEC-DEFI-002" {
		t.Errorf("rule = %v, want SOLSEC-DEFI-002", findings[0].RuleID)
	}
}

func TestFlashLoan_ReceiverSafe_WithCallerCheck(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
contract Receiver {
    address public lender;
    function onFlashLoan(address, address token, uint256 amount, uint256 fee, bytes calldata)
        external returns (bytes32) {
        require(msg.sender == lender, "untrusted");
        IERC20(token).approve(msg.sender, amount + fee);
        return keccak256("ERC3156FlashBorrower.onFlashLoan");
    }
}`
	d := detectors.NewFlashLoanDetector()
	findings, _ := d.Analyze(strings.Split(source, "\n"), source, "T.sol")

	if len(findings) != 0 {
		t.Errorf("caller verified = safe, got %d findings", len(findings))
	}
}

func TestFlashLoan_UniswapV2Call_NoAuth(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
contract Attacker {
    function uniswapV2Call(address sender, uint256 amount0, uint256 amount1, bytes calldata data)
        external {
        // No msg.sender check!
        IERC20(token).transfer(attacker, amount0);
    }
}`
	d := detectors.NewFlashLoanDetector()
	findings, _ := d.Analyze(strings.Split(source, "\n"), source, "T.sol")

	if len(findings) == 0 {
		t.Fatal("uniswapV2Call without auth = HIGH expected")
	}
}

func TestFlashLoan_ExecuteOperation_AaveStyle_NoAuth(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
contract FlashBorrower {
    function executeOperation(
        address[] calldata assets,
        uint256[] calldata amounts,
        uint256[] calldata premiums,
        address initiator,
        bytes calldata params
    ) external returns (bool) {
        // No require(msg.sender == POOL)!
        IERC20(assets[0]).approve(msg.sender, amounts[0] + premiums[0]);
        return true;
    }
}`
	d := detectors.NewFlashLoanDetector()
	findings, _ := d.Analyze(strings.Split(source, "\n"), source, "T.sol")

	if len(findings) == 0 {
		t.Fatal("executeOperation without caller check = HIGH expected")
	}
}

func TestFlashLoan_InternalFunction_Ignored(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
contract Pool {
    function flashLoan(address receiver, uint256 amount) internal {
        IFlashBorrower(receiver).onFlashLoan(amount);
    }
}`
	d := detectors.NewFlashLoanDetector()
	findings, _ := d.Analyze(strings.Split(source, "\n"), source, "T.sol")

	if len(findings) != 0 {
		t.Errorf("internal function = skip, got %d findings", len(findings))
	}
}
