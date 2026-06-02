package detectors_test

import (
	"strings"
	"testing"

	"github.com/ayb-blc/solsec/internal/analyzer"
	"github.com/ayb-blc/solsec/internal/detectors"
)

func TestReentrancyDetector(t *testing.T) {
	d := detectors.NewReentrancyDetector()

	cases := []DetectorTestCase{
		// --- TRUE POSITIVE TESTLER ---

		{
			Name:             "basic CEI violation",
			ContractFile:     "vulnerable/reentrancy/basic.sol",
			ExpectedFindings: 1,
			ExpectedSeverity: analyzer.Critical,
			ExpectedDetector: "reentrancy",
		},
		{
			Name:             "multiple withdraw functions",
			ContractFile:     "vulnerable/reentrancy/multi_withdraw.sol",
			ExpectedFindings: 2,
		},
		{
			Name:             "ETH send instead of call",
			ContractFile:     "vulnerable/reentrancy/using_send.sol",
			ExpectedFindings: 1,
		},
		{
			Name:             "transfer then state update",
			ContractFile:     "vulnerable/reentrancy/transfer_pattern.sol",
			ExpectedFindings: 1,
			ShouldFindLine:   15,
		},

		// --- FALSE POSITIVE TESTLER ---

		{
			Name:             "ReentrancyGuard protected",
			ContractFile:     "safe/reentrancy/with_guard.sol",
			ExpectedFindings: 0,
		},
		{
			Name:             "correct CEI pattern",
			ContractFile:     "safe/reentrancy/cei_correct.sol",
			ExpectedFindings: 0,
		},
		{
			Name:             "view function with external call",
			ContractFile:     "safe/reentrancy/view_only.sol",
			ExpectedFindings: 0,
		},
		{
			Name:             "internal function no external caller",
			ContractFile:     "safe/reentrancy/internal_only.sol",
			ExpectedFindings: 0,
		},

		// --- EDGE CASE TESTLER ---

		{
			Name:             "empty contract",
			ContractFile:     "edge/empty_contract.sol",
			ExpectedFindings: 0,
		},
		{
			Name:             "call in require statement",
			ContractFile:     "edge/call_in_require.sol",
			ExpectedFindings: 1,
		},
		{
			Name:             "nested function calls",
			ContractFile:     "edge/nested_calls.sol",
			ExpectedFindings: -1, // En az bir finding
		},
	}

	RunDetectorTests(t, d, cases)
}

func TestReentrancyDetector_InlineContracts(t *testing.T) {
	d := detectors.NewReentrancyDetector()

	tests := []struct {
		name              string
		source            string
		wantFindings      int
		wantTitleContains string
	}{
		{
			name: "call before state update",
			source: `
pragma solidity ^0.8.0;
contract T {
    mapping(address => uint256) balances;
    function withdraw() external {
        (bool ok,) = msg.sender.call{value: balances[msg.sender]}("");
        balances[msg.sender] = 0;
    }
}`,
			wantFindings:      1,
			wantTitleContains: "withdraw",
		},
		{
			name: "state update before call - safe",
			source: `
pragma solidity ^0.8.0;
contract T {
    mapping(address => uint256) balances;
    function withdraw() external {
        uint256 amt = balances[msg.sender];
        balances[msg.sender] = 0;
        (bool ok,) = msg.sender.call{value: amt}("");
    }
}`,
			wantFindings: 0,
		},
		{
			name: "nonReentrant modifier - safe",
			source: `
pragma solidity ^0.8.0;
abstract contract ReentrancyGuard {
    bool private locked;
    modifier nonReentrant() {
        require(!locked);
        locked = true;
        _;
        locked = false;
    }
}
contract T is ReentrancyGuard {
    mapping(address => uint256) balances;
    function withdraw() external nonReentrant {
        (bool ok,) = msg.sender.call{value: balances[msg.sender]}("");
        balances[msg.sender] = 0;
    }
}`,
			wantFindings: 0,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			lines := strings.Split(tt.source, "\n")
			findings, err := d.Analyze(lines, tt.source, "inline_test.sol")
			if err != nil {
				t.Fatalf("analyze error: %v", err)
			}

			if len(findings) != tt.wantFindings {
				t.Errorf("want %d findings, got %d\nfindings: %s",
					tt.wantFindings, len(findings), formatFindings(findings))
			}

			if tt.wantTitleContains != "" && len(findings) > 0 {
				found := false
				for _, f := range findings {
					if strings.Contains(f.Title, tt.wantTitleContains) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("no finding title contains %q\nfindings: %s",
						tt.wantTitleContains, formatFindings(findings))
				}
			}
		})
	}
}

func TestReentrancyDetector_Regression(t *testing.T) {
	d := detectors.NewReentrancyDetector()

	t.Run("issue-42: false positive on library call", func(t *testing.T) {
		source := `
pragma solidity ^0.7.0;
import "./SafeMath.sol";
contract T {
    using SafeMath for uint256;
    mapping(address => uint256) balances;
    function add(uint256 a, uint256 b) external {
        balances[msg.sender] = balances[msg.sender].add(b);
    }
}`
		lines := strings.Split(source, "\n")
		findings, _ := d.Analyze(lines, source, "regression_42.sol")
		if len(findings) > 0 {
			t.Errorf("regression issue-42: library call should not be flagged, got %d findings",
				len(findings))
		}
	})

	t.Run("issue-67: false negative on send()", func(t *testing.T) {
		source := `
pragma solidity ^0.8.0;
contract T {
    mapping(address => uint256) balances;
    function withdraw() external {
        bool sent = payable(msg.sender).send(balances[msg.sender]);
        require(sent);
        balances[msg.sender] = 0;
    }
}`
		lines := strings.Split(source, "\n")
		findings, _ := d.Analyze(lines, source, "regression_67.sol")
		if len(findings) == 0 {
			t.Error("regression issue-67: .send() before state update should be flagged")
		}
	})
}
