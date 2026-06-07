// internal/detectors/storage_gap_missing_test.go

package detectors_test

import (
	"strings"
	"testing"

	"github.com/ayb-blc/solsec/internal/analyzer"
	"github.com/ayb-blc/solsec/internal/detectors"
	"github.com/ayb-blc/solsec/internal/testutil"
)

func TestStorageGapMissing_Fixtures(t *testing.T) {
	d := detectors.NewStorageGapMissingDetector()
	for _, fixture := range testutil.LoadFixtures(t, "../../testdata/fixtures/init/gap_*.sol") {
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

func TestStorageGapMissing_AbstractBase_Low(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

abstract contract BaseVault is Initializable {
    uint256 public fee;
    address public treasury;
    function initialize() external initializer {}
}`
	d := detectors.NewStorageGapMissingDetector()
	findings, _ := d.Analyze(strings.Split(source, "\n"), source, "T.sol")

	if len(findings) == 0 {
		t.Fatal("abstract base without gap = LOW expected")
	}
	if findings[0].Severity != analyzer.Low {
		t.Errorf("severity = %v, want LOW (abstract base)", findings[0].Severity)
	}
	if findings[0].Confidence != analyzer.ConfidenceLow {
		t.Errorf("confidence = %v, want LOW", findings[0].Confidence)
	}
}

func TestStorageGapMissing_InheritedBase_Low(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
contract BaseLogic {
    uint256 public version;
    function initialize() external {}
}
contract ChildLogic is BaseLogic {
    uint256 public balance;
}`
	d := detectors.NewStorageGapMissingDetector()
	findings, _ := d.Analyze(strings.Split(source, "\n"), source, "T.sol")

	if len(findings) == 0 {
		t.Fatal("inherited base without gap = LOW expected")
	}
	if findings[0].Severity != analyzer.Low {
		t.Errorf("severity = %v, want LOW (inherited by ChildLogic)", findings[0].Severity)
	}
}

func TestStorageGapMissing_LeafContract_Low(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

contract LeafVault is Initializable {
    uint256 public fee;
    function initialize() external initializer {}
}`
	d := detectors.NewStorageGapMissingDetector()
	findings, _ := d.Analyze(strings.Split(source, "\n"), source, "T.sol")

	if len(findings) == 0 {
		t.Fatal("leaf without gap = LOW expected")
	}
	if findings[0].Severity != analyzer.Low {
		t.Errorf("severity = %v, want LOW (leaf contract)", findings[0].Severity)
	}
}

func TestStorageGapMissing_Safe_GapPresent(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
abstract contract SafeBase {
    uint256 public fee;
    address public treasury;
    uint256[48] private __gap;
    function initialize() external {}
}`
	d := detectors.NewStorageGapMissingDetector()
	findings, _ := d.Analyze(strings.Split(source, "\n"), source, "T.sol")

	if len(findings) != 0 {
		t.Errorf("__gap present = safe, got %d findings", len(findings))
	}
}

func TestStorageGapMissing_Safe_ConstantsOnly(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
abstract contract ConstBase {
    uint256 public constant VERSION = 1;
    address public immutable FACTORY;
    function initialize() external {}
}`
	d := detectors.NewStorageGapMissingDetector()
	findings, _ := d.Analyze(strings.Split(source, "\n"), source, "T.sol")

	if len(findings) != 0 {
		t.Errorf("constants only = no storage slots, got %d findings", len(findings))
	}
}

func TestStorageGapMissing_Safe_NotUpgradeable(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
contract RegularBase {
    uint256 public fee;
    address public owner;
}
contract RegularChild is RegularBase {
    uint256 public balance;
}`
	d := detectors.NewStorageGapMissingDetector()
	findings, _ := d.Analyze(strings.Split(source, "\n"), source, "T.sol")

	if len(findings) != 0 {
		t.Errorf("non-upgradeable = no finding, got %d", len(findings))
	}
}

func TestStorageGapMissing_VirtualFunctions_Low(t *testing.T) {
	source := `
pragma solidity ^0.8.0;
contract VirtualBase {
    uint256 public fee;
    function initialize() external {}
    function _transfer(address to, uint256 amount) internal virtual {}
}`
	d := detectors.NewStorageGapMissingDetector()
	findings, _ := d.Analyze(strings.Split(source, "\n"), source, "T.sol")

	if len(findings) == 0 {
		t.Fatal("virtual functions = base signal, LOW expected")
	}
	if findings[0].Severity != analyzer.Low {
		t.Errorf("severity = %v, want LOW (has virtual functions)", findings[0].Severity)
	}
}
