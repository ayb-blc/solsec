// internal/detectors/constructor_in_upgradeable_test.go

package detectors_test

import (
	"strings"
	"testing"

	"github.com/ayb-blc/solsec/internal/analyzer"
	"github.com/ayb-blc/solsec/internal/detectors"
	"github.com/ayb-blc/solsec/internal/testutil"
)

func TestConstructorInUpgradeable_Fixtures(t *testing.T) {
	d := detectors.NewConstructorInUpgradeableDetector()
	for _, fixture := range testutil.LoadFixtures(t, "../../testdata/fixtures/init/constructor_*.sol") {
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

func TestConstructorInUpgradeable_SafeDisableInitializers(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
contract T is Initializable {
    address public owner;
    constructor() {
        _disableInitializers();
    }
    function initialize(address o) external initializer {
        owner = o;
    }
}`
	d := detectors.NewConstructorInUpgradeableDetector()
	findings, _ := d.Analyze(strings.Split(source, "\n"), source, "T.sol")

	if len(findings) != 0 {
		t.Errorf("_disableInitializers() = safe pattern, got %d findings", len(findings))
	}
}

func TestConstructorInUpgradeable_SafeEmptyConstructor(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
contract T is Initializable {
    constructor() {}
    function initialize() external initializer {}
}`
	d := detectors.NewConstructorInUpgradeableDetector()
	findings, _ := d.Analyze(strings.Split(source, "\n"), source, "T.sol")

	if len(findings) != 0 {
		t.Errorf("empty constructor = safe, got %d findings", len(findings))
	}
}

func TestConstructorInUpgradeable_CriticalOwnerSet(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
contract Vault is Initializable, OwnableUpgradeable {
    constructor(address owner_) {
        _transferOwnership(owner_);
    }
    function initialize() external initializer {}
}`
	d := detectors.NewConstructorInUpgradeableDetector()
	findings, _ := d.Analyze(strings.Split(source, "\n"), source, "T.sol")

	if len(findings) == 0 {
		t.Fatal("constructor setting owner in upgradeable = CRITICAL finding expected")
	}
	if findings[0].Severity != analyzer.Critical {
		t.Errorf("severity = %v, want CRITICAL", findings[0].Severity)
	}
}

func TestConstructorInUpgradeable_HighNonCriticalState(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
contract T is Initializable {
    uint256 public fee;
    constructor(uint256 fee_) {
        fee = fee_;
    }
    function initialize() external initializer {}
}`
	d := detectors.NewConstructorInUpgradeableDetector()
	findings, _ := d.Analyze(strings.Split(source, "\n"), source, "T.sol")

	if len(findings) == 0 {
		t.Fatal("state write in upgradeable constructor = HIGH finding expected")
	}
	if findings[0].Severity != analyzer.High {
		t.Errorf("severity = %v, want HIGH", findings[0].Severity)
	}
}

func TestConstructorInUpgradeable_NotUpgradeable_NoFinding(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
contract RegularVault {
    address public owner;
    constructor(address owner_) {
        owner = owner_;
    }
}`
	d := detectors.NewConstructorInUpgradeableDetector()
	findings, _ := d.Analyze(strings.Split(source, "\n"), source, "T.sol")

	if len(findings) != 0 {
		t.Errorf("regular contract constructor = no finding, got %d", len(findings))
	}
}

func TestConstructorInUpgradeable_CriticalGrantRole(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
contract T is Initializable {
    bytes32 constant ADMIN = keccak256("ADMIN");
    constructor() {
        grantRole(ADMIN, msg.sender);
    }
    function initialize() external initializer {}
}`
	d := detectors.NewConstructorInUpgradeableDetector()
	findings, _ := d.Analyze(strings.Split(source, "\n"), source, "T.sol")

	if len(findings) == 0 {
		t.Fatal("grantRole in upgradeable constructor = CRITICAL expected")
	}
	if findings[0].Severity != analyzer.Critical {
		t.Errorf("severity = %v, want CRITICAL", findings[0].Severity)
	}
}

func TestConstructorInUpgradeable_SafeCommentedCode(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
contract T is Initializable {
    address public owner;
    constructor() {
        // owner = msg.sender; ← commented out, NOT state write
        _disableInitializers();
    }
    function initialize(address o) external initializer {
        owner = o;
    }
}`
	d := detectors.NewConstructorInUpgradeableDetector()
	findings, _ := d.Analyze(strings.Split(source, "\n"), source, "T.sol")

	if len(findings) != 0 {
		t.Errorf("commented code should not trigger, got %d findings", len(findings))
	}
}
