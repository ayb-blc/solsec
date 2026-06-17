package detectors_test

import (
	"os"
	"strings"
	"testing"

	"github.com/ayb-blc/solsec/internal/analyzer"
	"github.com/ayb-blc/solsec/internal/detectors"
	"github.com/ayb-blc/solsec/internal/rules"
)

func TestReinitializableInit_CriticalPrivilegedState(t *testing.T) {
	findings := analyzeInitFixture(t, "../../testdata/fixtures/init/vulnerable_critical.sol")
	if len(findings) != 1 {
		t.Fatalf("findings=%d, want 1", len(findings))
	}
	if findings[0].RuleID != rules.IDInit001 {
		t.Fatalf("RuleID=%s, want %s", findings[0].RuleID, rules.IDInit001)
	}
	if findings[0].Severity != analyzer.Critical {
		t.Fatalf("Severity=%s, want CRITICAL", findings[0].Severity)
	}
}

func TestReinitializableInit_HighNonCriticalState(t *testing.T) {
	findings := analyzeInitFixture(t, "../../testdata/fixtures/init/vulnerable_high.sol")
	if len(findings) != 1 {
		t.Fatalf("findings=%d, want 1", len(findings))
	}
	if findings[0].Severity != analyzer.High {
		t.Fatalf("Severity=%s, want HIGH", findings[0].Severity)
	}
}

func TestReinitializableInit_SafeFixtures(t *testing.T) {
	for _, path := range []string{
		"../../testdata/fixtures/init/safe_initializer_modifier.sol",
		"../../testdata/fixtures/init/safe_manual_flag.sol",
		"../../testdata/fixtures/init/safe_onlyowner_setup.sol",
	} {
		t.Run(path, func(t *testing.T) {
			findings := analyzeInitFixture(t, path)
			if len(findings) != 0 {
				t.Fatalf("expected no findings, got %d: %#v", len(findings), findings)
			}
		})
	}
}

func TestReinitializableInit_MultilineInitializerModifier_NoFinding(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
contract Token {
    modifier initializer() { _; }
    function initialize(
        address pool,
        string memory name,
        string memory symbol
    )
        external
        initializer
    {
        pool;
        name;
        symbol;
    }
}`
	d := detectors.NewReinitializableInitDetector()
	findings, err := d.Analyze(strings.Split(source, "\n"), source, "Token.sol")
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %d: %#v", len(findings), findings)
	}
}

func TestReinitializableInit_ProxyImplementationGuard_NoFinding(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
contract InitializableUpgradeabilityProxy {
    function initialize(address logic, bytes memory data) public payable {
        require(_implementation() == address(0));
        _setImplementation(logic);
        data;
    }
    function _implementation() internal view returns (address) {}
    function _setImplementation(address logic) internal {}
}`
	d := detectors.NewReinitializableInitDetector()
	findings, err := d.Analyze(strings.Split(source, "\n"), source, "Proxy.sol")
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %d: %#v", len(findings), findings)
	}
}

func TestReinitializableInit_InterfaceAndLibrary_NoFinding(t *testing.T) {
	source := `
pragma solidity >=0.5.0;

interface IPoolActions {
    function initialize(uint160 sqrtPriceX96) external;
}

library Oracle {
    struct Observation { bool initialized; }
    function initialize(Observation[65535] storage self) internal {
        self[0] = Observation({initialized: true});
    }
}`
	d := detectors.NewReinitializableInitDetector()
	findings, err := d.Analyze(strings.Split(source, "\n"), source, "Pool.sol")
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("interface/library initialize should not trigger, got %d: %#v", len(findings), findings)
	}
}

func TestReinitializableInit_ZeroStateGuard_NoFinding(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
contract Pool {
    struct Slot0 { uint160 sqrtPriceX96; bool unlocked; }
    Slot0 public slot0;
    function initialize(uint160 sqrtPriceX96) external {
        require(slot0.sqrtPriceX96 == 0, "already initialized");
        slot0 = Slot0({sqrtPriceX96: sqrtPriceX96, unlocked: true});
    }
}`
	d := detectors.NewReinitializableInitDetector()
	findings, err := d.Analyze(strings.Split(source, "\n"), source, "Pool.sol")
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("zero state guard should suppress initialize finding, got %d", len(findings))
	}
}

func analyzeInitFixture(t *testing.T, path string) []analyzer.Finding {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	source := string(data)
	findings, err := detectors.NewReinitializableInitDetector().Analyze(strings.Split(source, "\n"), source, path)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	return findings
}
